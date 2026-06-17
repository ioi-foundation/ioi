import { NotificationTargetDetailSections } from "./NotificationTargetDetailSections";
import type { NotificationTargetDetailClassNames } from "./NotificationTargetDetailSections";
import { useNotificationTargetDetail } from "../hooks/useNotificationTargetDetail";
import {
  humanizeOperatorNotificationValue,
  isLocalEngineIntervention,
} from "../lib/operatorNotifications";
import { notificationTargetConnectorId } from "../lib/notificationTargets";
import type {
  AssistantNotificationRecord,
  AssistantWorkbenchSession,
  InterventionRecord,
} from "../types";

type NotificationDetailItem = AssistantNotificationRecord | InterventionRecord;

type OperatorNotificationDetailProps = {
  item: NotificationDetailItem | null;
  containerTag: "aside" | "section";
  onClose: () => void;
  onOpenChat: () => void;
  onOpenInbox?: () => void;
  onOpenReplyComposer: (
    session: Extract<AssistantWorkbenchSession, { kind: "gmail_reply" }>,
  ) => void;
  onOpenMeetingPrep: (
    session: Extract<AssistantWorkbenchSession, { kind: "meeting_prep" }>,
  ) => void;
  onOpenCapabilities: (connectorId?: string | null) => void;
  onOpenPolicy: (connectorId?: string | null) => void;
  onOpenLocalEngine: () => void;
  emptyState: {
    eyebrow: string;
    title: string;
    description: string;
  };
  copy: {
    close: string;
    openChat: string;
    openInbox?: string;
    openCapabilities: string;
    openPolicy: string;
    openLocalEngine: string;
  };
  classNames: {
    container: string;
    emptyContainer: string;
    head: string;
    eyebrow: string;
    quietButton: string;
    meta: string;
    section: string;
    card: string;
    engineCard: string;
    cardHead: string;
    tags: string;
    actions: string;
    primaryButton: string;
    secondaryButton: string;
    error: string;
    loadingCard: string;
    target: NotificationTargetDetailClassNames;
  };
};

function isInterventionRecord(item: NotificationDetailItem): item is InterventionRecord {
  return "interventionType" in item;
}

function formatAbsoluteTime(timestampMs?: number | null): string {
  if (!timestampMs) return "Unknown";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(timestampMs));
}

export function OperatorNotificationDetail({
  item,
  containerTag,
  onClose,
  onOpenChat,
  onOpenInbox,
  onOpenReplyComposer,
  onOpenMeetingPrep,
  onOpenCapabilities,
  onOpenPolicy,
  onOpenLocalEngine,
  emptyState,
  copy,
  classNames,
}: OperatorNotificationDetailProps) {
  const {
    loading,
    busy,
    error,
    gmailThread,
    calendarEvent,
    authRecord,
    subscription,
    runSubscriptionAction,
  } = useNotificationTargetDetail(item);

  const ContainerTag = containerTag;

  if (!item) {
    return (
      <ContainerTag className={`${classNames.container} ${classNames.emptyContainer}`}>
        <div>
          <span className={classNames.eyebrow}>{emptyState.eyebrow}</span>
          <h2>{emptyState.title}</h2>
          <p>{emptyState.description}</p>
        </div>
      </ContainerTag>
    );
  }

  const isIntervention = isInterventionRecord(item);
  const connectorId = notificationTargetConnectorId(item.target);
  const detailType = isIntervention
    ? humanizeOperatorNotificationValue(item.interventionType)
    : humanizeOperatorNotificationValue(item.notificationClass);

  return (
    <ContainerTag className={classNames.container}>
      <div className={classNames.head}>
        <div>
          <span className={classNames.eyebrow}>{detailType}</span>
          <h2>{item.title}</h2>
          <p>{item.summary}</p>
        </div>
        <button
          type="button"
          className={classNames.quietButton}
          onClick={onClose}
        >
          {copy.close}
        </button>
      </div>

      <div className={classNames.meta}>
        <span>{humanizeOperatorNotificationValue(item.status)}</span>
        <span>{humanizeOperatorNotificationValue(item.severity)}</span>
        <span>{item.source.serviceName}</span>
        {item.dueAtMs ? <span>Due {formatAbsoluteTime(item.dueAtMs)}</span> : null}
        <span>Updated {formatAbsoluteTime(item.updatedAtMs)}</span>
      </div>

      <section className={classNames.section}>
        {isIntervention && isLocalEngineIntervention(item) ? (
          <article className={classNames.engineCard}>
            <div className={classNames.cardHead}>
              <strong>Local engine control plane</strong>
              <span>Kernel-managed</span>
            </div>
            <p>
              This intervention routes through the Local Engine control plane,
              so review and lifecycle receipts stay in the governed runtime.
            </p>
            <div className={classNames.tags}>
              <span>{item.approvalScope || "model::control"}</span>
              {item.sensitiveActionType ? (
                <span>{humanizeOperatorNotificationValue(item.sensitiveActionType)}</span>
              ) : null}
              {item.requestHash ? <span>Request {item.requestHash.slice(0, 12)}</span> : null}
            </div>
            {item.recoveryHint ? <p>{item.recoveryHint}</p> : null}
          </article>
        ) : null}

        <article className={classNames.card}>
          <div className={classNames.cardHead}>
            <strong>Why this surfaced</strong>
          </div>
          {item.reason ? <p>{item.reason}</p> : <p>{item.summary}</p>}
          {item.recommendedAction ? <p>Next: {item.recommendedAction}</p> : null}
          {item.consequenceIfIgnored ? (
            <p>If ignored: {item.consequenceIfIgnored}</p>
          ) : null}
        </article>

        <article className={classNames.card}>
          <div className={classNames.cardHead}>
            <strong>Context</strong>
          </div>
          <div className={classNames.tags}>
            {item.workflowId ? <span>Workflow {item.workflowId}</span> : null}
            {item.runId ? <span>Run {item.runId}</span> : null}
            {item.sessionId ? <span>Session {item.sessionId.slice(0, 8)}</span> : null}
            {item.threadId ? <span>Thread {item.threadId.slice(0, 8)}</span> : null}
            {item.artifactRefs.length > 0 ? (
              <span>{item.artifactRefs.length} artifacts</span>
            ) : null}
          </div>
          {isIntervention ? (
            <>
              <div className={classNames.tags}>
                {item.blocking ? <span>Blocking</span> : null}
                {item.approvalScope ? (
                  <span>{humanizeOperatorNotificationValue(item.approvalScope)}</span>
                ) : null}
                {item.sensitiveActionType ? (
                  <span>{humanizeOperatorNotificationValue(item.sensitiveActionType)}</span>
                ) : null}
                {item.blockedStage ? (
                  <span>{humanizeOperatorNotificationValue(item.blockedStage)}</span>
                ) : null}
                {item.retryAvailable ? <span>Retry available</span> : null}
              </div>
              {item.recoveryHint ? <p>{item.recoveryHint}</p> : null}
            </>
          ) : (
            <>
              <div className={classNames.tags}>
                <span>Priority {(item.priorityScore * 100).toFixed(0)}%</span>
                <span>Confidence {(item.confidenceScore * 100).toFixed(0)}%</span>
                {item.rankingReason.slice(0, 3).map((reason) => (
                  <span key={reason}>{humanizeOperatorNotificationValue(reason)}</span>
                ))}
              </div>
              <p>
                Observation tier:{" "}
                {humanizeOperatorNotificationValue(item.privacy.observationTier)}
              </p>
            </>
          )}
        </article>

        <div className={classNames.actions}>
          {isIntervention && isLocalEngineIntervention(item) ? (
            <button
              type="button"
              className={classNames.primaryButton}
              onClick={onOpenLocalEngine}
            >
              {copy.openLocalEngine}
            </button>
          ) : null}
          <button
            type="button"
            className={
              isIntervention && isLocalEngineIntervention(item)
                ? classNames.secondaryButton
                : classNames.primaryButton
            }
            onClick={onOpenChat}
          >
            {copy.openChat}
          </button>
          {onOpenInbox && copy.openInbox ? (
            <button
              type="button"
              className={classNames.secondaryButton}
              onClick={onOpenInbox}
            >
              {copy.openInbox}
            </button>
          ) : null}
          {connectorId ? (
            <button
              type="button"
              className={classNames.secondaryButton}
              onClick={() => onOpenCapabilities(connectorId)}
            >
              {copy.openCapabilities}
            </button>
          ) : null}
          {connectorId ? (
            <button
              type="button"
              className={classNames.quietButton}
              onClick={() => onOpenPolicy(connectorId)}
            >
              {copy.openPolicy}
            </button>
          ) : null}
        </div>
      </section>

      {loading ? <div className={classNames.loadingCard}>Loading target detail…</div> : null}
      {error ? <div className={classNames.error}>{error}</div> : null}

      {!loading && !error && item.target ? (
        <NotificationTargetDetailSections
          item={item}
          gmailThread={gmailThread}
          calendarEvent={calendarEvent}
          authRecord={authRecord}
          subscription={subscription}
          busy={busy}
          runSubscriptionAction={runSubscriptionAction}
          onOpenReplyComposer={onOpenReplyComposer}
          onOpenMeetingPrep={onOpenMeetingPrep}
          onOpenCapabilities={onOpenCapabilities}
          onOpenPolicy={onOpenPolicy}
          onOpenInbox={onOpenInbox}
          classNames={classNames.target}
          maxMessages={3}
          maxAttendees={5}
          maxMetadataEntries={5}
          showCalendarExternalLink={true}
          showCalendarCapabilitiesAction={true}
        />
      ) : null}

      {!loading && !error && !item.target ? (
        <div className={classNames.card}>
          No target detail is attached to this notification yet.
        </div>
      ) : null}
    </ContainerTag>
  );
}
