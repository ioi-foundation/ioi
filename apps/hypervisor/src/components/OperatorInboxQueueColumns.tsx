import {
  INBOX_LANES,
  type InboxLane,
  type InboxQueueItem,
} from "../lib/operatorInboxQueue";
import {
  displayNotificationActionLabel,
  isLocalEngineIntervention,
  isResolvedAssistant,
  isResolvedIntervention,
  pickPrimaryAssistantAction,
} from "../lib/operatorNotifications";
import type {
  AssistantNotificationRecord,
  InterventionRecord,
} from "../types";

function formatAbsoluteTime(timestampMs?: number | null): string {
  if (!timestampMs) return "No deadline";
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(timestampMs));
}

function formatRelativeTime(timestampMs: number): string {
  const deltaMs = timestampMs - Date.now();
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const minuteMs = 60_000;
  const hourMs = 60 * minuteMs;
  const dayMs = 24 * hourMs;

  if (Math.abs(deltaMs) < hourMs) {
    return formatter.format(Math.round(deltaMs / minuteMs), "minute");
  }
  if (Math.abs(deltaMs) < dayMs) {
    return formatter.format(Math.round(deltaMs / hourMs), "hour");
  }
  return formatter.format(Math.round(deltaMs / dayMs), "day");
}

function dueCopy(dueAtMs?: number | null): string | null {
  if (!dueAtMs) return null;
  return `${formatRelativeTime(dueAtMs)} (${formatAbsoluteTime(dueAtMs)})`;
}

type OperatorInboxQueueColumnsProps = {
  activeLane: InboxLane;
  laneCounts: Record<InboxLane, number>;
  searchDraft: string;
  filteredQueueItems: InboxQueueItem[];
  selectedItemKey: string | null;
  className?: string;
  actionError?: string | null;
  notificationsError?: string | null;
  notificationsLoading?: boolean;
  embedded?: boolean;
  queueEyebrow?: string;
  toolbarActionLabel?: string | null;
  onLaneChange: (lane: InboxLane) => void;
  onSearchDraftChange: (value: string) => void;
  onSelectItemKey: (key: string) => void;
  onToolbarAction?: () => void;
  onOpenAutopilot: () => void;
  onOpenLocalEngine: () => void;
  onAssistantAction: (
    item: AssistantNotificationRecord,
    actionId: string,
  ) => Promise<void> | void;
  onDeferAssistant: (
    item: AssistantNotificationRecord,
  ) => Promise<void> | void;
  onDeferIntervention: (
    item: InterventionRecord,
  ) => Promise<void> | void;
};

export function OperatorInboxQueueColumns({
  activeLane,
  laneCounts,
  searchDraft,
  filteredQueueItems,
  selectedItemKey,
  className,
  actionError,
  notificationsError,
  notificationsLoading = false,
  embedded = false,
  queueEyebrow = "Operations Queue",
  toolbarActionLabel = "Inbox settings",
  onLaneChange,
  onSearchDraftChange,
  onSelectItemKey,
  onToolbarAction,
  onOpenAutopilot,
  onOpenLocalEngine,
  onAssistantAction,
  onDeferAssistant,
  onDeferIntervention,
}: OperatorInboxQueueColumnsProps) {
  return (
    <div
      className={[
        embedded ? "notifications-queue-columns notifications-queue-columns--embedded" : "notifications-shell",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <aside className="notifications-sidebar">
        <div className="notifications-sidebar-head">
          <strong>Queues</strong>
          <span>Filter</span>
        </div>
        <div className="notifications-filter-list">
          {INBOX_LANES.map((lane) => (
            <button
              key={lane.id}
              type="button"
              className={`notifications-filter-button ${activeLane === lane.id ? "active" : ""}`}
              onClick={() => onLaneChange(lane.id)}
            >
              <div>
                <strong>{lane.label}</strong>
                <span>{lane.description}</span>
              </div>
              <em>{laneCounts[lane.id]}</em>
            </button>
          ))}
        </div>
      </aside>

      <section className="notifications-queue-pane">
        <div className="notifications-queue-toolbar">
          <input
            className="notifications-search-input"
            type="search"
            value={searchDraft}
            onChange={(event) => onSearchDraftChange(event.target.value)}
            placeholder="Search title, workflow, run, or action"
          />
          {onToolbarAction && toolbarActionLabel ? (
            <button
              type="button"
              className="notifications-secondary-button"
              onClick={onToolbarAction}
            >
              {toolbarActionLabel}
            </button>
          ) : null}
        </div>

        <div className="notifications-queue-head">
          <div>
            <span className="notifications-card-eyebrow">{queueEyebrow}</span>
            <h2>
              {INBOX_LANES.find((lane) => lane.id === activeLane)?.label ?? "All"}{" "}
              items
            </h2>
          </div>
          <span className="notifications-queue-count">
            {filteredQueueItems.length}
          </span>
        </div>

        {actionError ? <p className="notifications-error">{actionError}</p> : null}
        {notificationsError ? (
          <p className="notifications-error">{notificationsError}</p>
        ) : null}
        {notificationsLoading && filteredQueueItems.length === 0 ? (
          <div className="notifications-empty-card">Loading inbox…</div>
        ) : null}

        <div className="notifications-list">
          {!notificationsLoading && filteredQueueItems.length === 0 ? (
            <div className="notifications-empty-card">
              No inbox items match this queue.
            </div>
          ) : (
            filteredQueueItems.map((item) => {
              const relativeTime = formatRelativeTime(item.record.updatedAtMs);
              const dueLabel = dueCopy(item.record.dueAtMs);

              return (
                <article
                  key={item.key}
                  className={`notifications-card notifications-card-${item.record.severity}${
                    item.kind === "intervention" &&
                    isLocalEngineIntervention(item.record as InterventionRecord)
                      ? " notifications-card-engine"
                      : ""
                  }${
                    selectedItemKey === item.key
                      ? " notifications-card-selected"
                      : ""
                  }`}
                  onClick={() => onSelectItemKey(item.key)}
                >
                  <div className="notifications-card-topline">
                    <div className="notifications-card-badges">
                      <span
                        className={`notifications-pill notifications-pill-type-${item.typeLabel.toLowerCase()}`}
                      >
                        {item.typeLabel}
                      </span>
                      <span className="notifications-pill">{item.statusLabel}</span>
                      <span className="notifications-pill">{item.sourceLabel}</span>
                    </div>
                    <span className="notifications-card-time">
                      {dueLabel ? `Due ${dueLabel}` : relativeTime}
                    </span>
                  </div>

                  <div className="notifications-card-main">
                    <h3>{item.record.title}</h3>
                    <p className="notifications-summary">{item.record.summary}</p>
                  </div>

                  {item.meta.length > 0 ? (
                    <div className="notifications-meta">
                      {item.meta.map((value) => (
                        <span key={`${item.key}:${value}`}>{value}</span>
                      ))}
                    </div>
                  ) : null}

                  {item.record.recommendedAction ? (
                    <p className="notifications-next-step">
                      Next: {item.record.recommendedAction}
                    </p>
                  ) : null}

                  <div className="notifications-card-actions">
                    {item.kind === "assistant" ? (
                      <>
                        {pickPrimaryAssistantAction(
                          item.record as AssistantNotificationRecord,
                        ) ? (
                          <button
                            type="button"
                            className="notifications-primary-button"
                            onClick={(event) => {
                              event.stopPropagation();
                              const primaryAction = pickPrimaryAssistantAction(
                                item.record as AssistantNotificationRecord,
                              );
                              if (!primaryAction) return;
                              void onAssistantAction(
                                item.record as AssistantNotificationRecord,
                                primaryAction.id,
                              );
                            }}
                          >
                            {displayNotificationActionLabel(
                              pickPrimaryAssistantAction(
                                item.record as AssistantNotificationRecord,
                              )?.label,
                            )}
                          </button>
                        ) : (
                          <button
                            type="button"
                            className="notifications-primary-button"
                            onClick={(event) => {
                              event.stopPropagation();
                              void onAssistantAction(
                                item.record as AssistantNotificationRecord,
                                "open_target",
                              );
                            }}
                          >
                            Open
                          </button>
                        )}
                        <button
                          type="button"
                          className="notifications-secondary-button"
                          onClick={(event) => {
                            event.stopPropagation();
                            void onAssistantAction(
                              item.record as AssistantNotificationRecord,
                              isResolvedAssistant(
                                (item.record as AssistantNotificationRecord).status,
                              )
                                ? "archive"
                                : "snooze",
                            );
                          }}
                        >
                          {isResolvedAssistant(
                            (item.record as AssistantNotificationRecord).status,
                          )
                            ? "Archive"
                            : "Snooze 1h"}
                        </button>
                        {!isResolvedAssistant(
                          (item.record as AssistantNotificationRecord).status,
                        ) ? (
                          <button
                            type="button"
                            className="notifications-quiet-button"
                            onClick={(event) => {
                              event.stopPropagation();
                              void onDeferAssistant(
                                item.record as AssistantNotificationRecord,
                              );
                            }}
                          >
                            {(item.record as AssistantNotificationRecord).status ===
                            "new"
                              ? "Mark seen"
                              : "Snooze 1h"}
                          </button>
                        ) : null}
                      </>
                    ) : (
                      <>
                        <button
                          type="button"
                          className="notifications-primary-button"
                          onClick={(event) => {
                            event.stopPropagation();
                            if (
                              isLocalEngineIntervention(
                                item.record as InterventionRecord,
                              )
                            ) {
                              onOpenLocalEngine();
                              return;
                            }
                            onOpenAutopilot();
                          }}
                        >
                          {isLocalEngineIntervention(
                            item.record as InterventionRecord,
                          )
                            ? "Open local engine"
                            : "Open chat"}
                        </button>
                        {!isResolvedIntervention(
                          (item.record as InterventionRecord).status,
                        ) ? (
                          <button
                            type="button"
                            className="notifications-secondary-button"
                            onClick={(event) => {
                              event.stopPropagation();
                              void onDeferIntervention(
                                item.record as InterventionRecord,
                              );
                            }}
                          >
                            {(item.record as InterventionRecord).status === "new"
                              ? "Mark seen"
                              : "Snooze 1h"}
                          </button>
                        ) : null}
                      </>
                    )}
                  </div>
                </article>
              );
            })
          )}
        </div>
      </section>
    </div>
  );
}
