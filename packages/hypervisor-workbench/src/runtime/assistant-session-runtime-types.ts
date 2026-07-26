export type ChatViewTarget = string;

export type ChatCapabilityDetailSection =
  | "overview"
  | "setup"
  | "actions"
  | "policy";

export interface GmailThreadMessageDetail {
  id: string;
  from?: string;
  to?: string;
  subject?: string;
  date?: string;
  snippet?: string;
  rfcMessageId?: string;
  references?: string;
  labelIds: string[];
}

export interface GmailThreadDetail {
  threadId: string;
  historyId?: string;
  snippet?: string;
  messages: GmailThreadMessageDetail[];
}

export interface CalendarAttendeeDetail {
  email?: string;
  displayName?: string;
  responseStatus?: string;
  organizer?: boolean;
}

export interface CalendarEventDetail {
  calendarId: string;
  eventId: string;
  summary?: string;
  description?: string;
  location?: string;
  status?: string;
  start?: string;
  end?: string;
  htmlLink?: string;
  attendees: CalendarAttendeeDetail[];
}

export type AssistantWorkbenchSession =
  | {
      kind: "gmail_reply";
      connectorId: string;
      thread: GmailThreadDetail;
      sourceNotificationId?: string | null;
    }
  | {
      kind: "meeting_prep";
      connectorId: string;
      event: CalendarEventDetail;
      sourceNotificationId?: string | null;
    };

export type AssistantSessionEventName =
  | "task-started"
  | "task-updated"
  | "task-completed"
  | "task-dismissed"
  | "agent-event"
  | "artifact-created";

export interface AssistantSessionProjection<
  TSession = unknown,
  TSessionSummary = unknown,
> {
  task: TSession | null;
  sessions: TSessionSummary[];
}

export type AssistantWorkbenchActivityAction =
  | "open"
  | "draft"
  | "send"
  | "copy"
  | "hypervisor_handoff"
  | "shield_approval";

export type AssistantWorkbenchActivityStatus =
  | "started"
  | "succeeded"
  | "failed"
  | "requested";

export interface AssistantWorkbenchActivity {
  activityId: string;
  sessionKind: AssistantWorkbenchSession["kind"];
  surface: "reply-composer" | "meeting-prep";
  action: AssistantWorkbenchActivityAction;
  status: AssistantWorkbenchActivityStatus;
  message: string;
  timestampMs: number;
  sourceNotificationId?: string | null;
  connectorId?: string | null;
  threadId?: string | null;
  eventId?: string | null;
  evidenceThreadId?: string | null;
  detail?: string | null;
}

export interface AssistantSessionThreadLoadOptions {
  limit?: number;
  cursor?: number;
}

export interface AssistantSessionGateResponse {
  approved: boolean;
  requestHash?: string;
  action?: string;
}

export interface AssistantSessionRuntime {
  startSessionTask<T>(intent: string): Promise<T>;
  continueSessionTask(sessionId: string, userInput: string): Promise<void>;
  dismissSessionTask(): Promise<void>;
  stopSessionTask(): Promise<void>;
  getCurrentSessionTask<T>(): Promise<T | null>;
  listSessionHistory<T>(): Promise<T[]>;
  getSessionProjection<TSession, TSessionSummary>(): Promise<
    AssistantSessionProjection<TSession, TSessionSummary>
  >;
  loadSessionTask<T>(sessionId: string): Promise<T>;
  loadSessionThreadEvents<T>(
    threadId: string,
    options?: AssistantSessionThreadLoadOptions,
  ): Promise<T[]>;
  loadSessionThreadArtifacts<T>(threadId: string): Promise<T[]>;
  showPillShell(): Promise<void>;
  hidePillShell(): Promise<void>;
  showChatSessionShell(): Promise<void>;
  hideChatSessionShell(): Promise<void>;
  showChatShell(): Promise<void>;
  openChatView(view: ChatViewTarget): Promise<void>;
  openChatSessionTarget(sessionId: string): Promise<void>;
  openChatCapabilityTarget(
    connectorId?: string | null,
    detailSection?: ChatCapabilityDetailSection | null,
  ): Promise<void>;
  openChatPolicyTarget(connectorId?: string | null): Promise<void>;
  openChatAssistantWorkbench(
    session: AssistantWorkbenchSession,
  ): Promise<void>;
  activateAssistantWorkbenchSession(
    session: AssistantWorkbenchSession,
  ): Promise<void>;
  openChatHypervisorIntent(intent: string): Promise<void>;
  getActiveAssistantWorkbenchSession(): Promise<AssistantWorkbenchSession | null>;
  listenAssistantWorkbenchSession(
    handler: (session: AssistantWorkbenchSession) => void,
  ): Promise<() => void>;
  reportAssistantWorkbenchActivity(
    activity: AssistantWorkbenchActivity,
  ): Promise<void>;
  getRecentAssistantWorkbenchActivities?(
    limit?: number,
  ): Promise<AssistantWorkbenchActivity[]>;
  listenAssistantWorkbenchActivity(
    handler: (activity: AssistantWorkbenchActivity) => void,
  ): Promise<() => void>;
  submitSessionRuntimePassword(
    sessionId: string,
    password: string,
  ): Promise<void>;
  respondToSessionGate(input: AssistantSessionGateResponse): Promise<void>;
  listenSessionProjection<TSession, TSessionSummary>(
    handler: (projection: AssistantSessionProjection<TSession, TSessionSummary>) => void,
  ): Promise<() => void>;
  listenSessionEvent<T>(
    eventName: AssistantSessionEventName,
    handler: (payload: T) => void,
  ): Promise<() => void>;
}
