import type {
  AssistantWorkbenchActivity,
  AssistantWorkbenchActivityAction,
  AssistantWorkbenchActivityStatus,
  AssistantWorkbenchSession,
} from "./assistant-session-runtime-types";

export type AssistantWorkbenchSurface = "reply-composer" | "meeting-prep";

export function assistantWorkbenchSurfaceForSession(
  session: AssistantWorkbenchSession,
): AssistantWorkbenchSurface {
  return session.kind === "gmail_reply" ? "reply-composer" : "meeting-prep";
}

export function assistantWorkbenchActivityTargetKey(
  activity: Pick<
    AssistantWorkbenchActivity,
    "sessionKind" | "sourceNotificationId" | "threadId" | "eventId"
  >,
): string {
  if (activity.sourceNotificationId?.trim()) {
    return `${activity.sessionKind}:notif:${activity.sourceNotificationId.trim()}`;
  }
  if (activity.sessionKind === "gmail_reply" && activity.threadId?.trim()) {
    return `gmail_reply:thread:${activity.threadId.trim()}`;
  }
  if (activity.sessionKind === "meeting_prep" && activity.eventId?.trim()) {
    return `meeting_prep:event:${activity.eventId.trim()}`;
  }
  return `${activity.sessionKind}:unknown`;
}

export function assistantWorkbenchSessionTargetKey(
  session: AssistantWorkbenchSession,
): string {
  return assistantWorkbenchActivityTargetKey({
    sessionKind: session.kind,
    sourceNotificationId: session.sourceNotificationId ?? null,
    threadId: session.kind === "gmail_reply" ? session.thread.threadId : null,
    eventId: session.kind === "meeting_prep" ? session.event.eventId : null,
  });
}

function trimOrNull(value?: string | null): string | null {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

export function assistantWorkbenchEvidenceThreadId(
  activity: Pick<
    AssistantWorkbenchActivity,
    "sessionKind" | "sourceNotificationId" | "connectorId" | "threadId" | "eventId"
  >,
): string {
  const connectorId = trimOrNull(activity.connectorId) ?? "connector";
  const sourceNotificationId = trimOrNull(activity.sourceNotificationId);
  if (sourceNotificationId) {
    return `assistant-workbench:${activity.sessionKind}:notif:${sourceNotificationId}`;
  }

  if (activity.sessionKind === "gmail_reply") {
    const threadId = trimOrNull(activity.threadId) ?? "thread";
    return `assistant-workbench:gmail_reply:${connectorId}:thread:${threadId}`;
  }

  const eventId = trimOrNull(activity.eventId) ?? "event";
  return `assistant-workbench:meeting_prep:${connectorId}:event:${eventId}`;
}

export function assistantWorkbenchEvidenceThreadIdForSession(
  session: AssistantWorkbenchSession,
): string {
  return assistantWorkbenchEvidenceThreadId({
    sessionKind: session.kind,
    sourceNotificationId: session.sourceNotificationId ?? null,
    connectorId: session.connectorId,
    threadId: session.kind === "gmail_reply" ? session.thread.threadId : null,
    eventId: session.kind === "meeting_prep" ? session.event.eventId : null,
  });
}

function createActivityId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `workbench-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

export function createAssistantWorkbenchActivity(
  session: AssistantWorkbenchSession,
  params: {
    action: AssistantWorkbenchActivityAction;
    status: AssistantWorkbenchActivityStatus;
    message: string;
    detail?: string | null;
  },
): AssistantWorkbenchActivity {
  return {
    activityId: createActivityId(),
    sessionKind: session.kind,
    surface: assistantWorkbenchSurfaceForSession(session),
    action: params.action,
    status: params.status,
    message: params.message,
    timestampMs: Date.now(),
    sourceNotificationId: session.sourceNotificationId ?? null,
    connectorId: session.connectorId,
    threadId: session.kind === "gmail_reply" ? session.thread.threadId : null,
    eventId: session.kind === "meeting_prep" ? session.event.eventId : null,
    evidenceThreadId: assistantWorkbenchEvidenceThreadIdForSession(session),
    detail: params.detail ?? null,
  };
}
