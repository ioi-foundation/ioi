export type StudioViewTarget = string;

export type StudioCapabilityDetailSection =
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
  | "autopilot_handoff"
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
  startAssistantSession?<T>(intent: string): Promise<T>;
  startSessionTask<T>(intent: string): Promise<T>;
  submitAssistantSessionInput?(
    sessionId: string,
    userInput: string,
  ): Promise<void>;
  continueSessionTask(sessionId: string, userInput: string): Promise<void>;
  dismissAssistantSession?(): Promise<void>;
  dismissSessionTask(): Promise<void>;
  stopAssistantSession?(): Promise<void>;
  stopSessionTask(): Promise<void>;
  getActiveAssistantSession?<T>(): Promise<T | null>;
  getCurrentSessionTask<T>(): Promise<T | null>;
  listAssistantSessions?<T>(): Promise<T[]>;
  listSessionHistory<T>(): Promise<T[]>;
  getAssistantSessionProjection?<TSession, TSessionSummary>(): Promise<
    AssistantSessionProjection<TSession, TSessionSummary>
  >;
  getSessionProjection<TSession, TSessionSummary>(): Promise<
    AssistantSessionProjection<TSession, TSessionSummary>
  >;
  loadAssistantSession?<T>(sessionId: string): Promise<T>;
  loadSessionTask<T>(sessionId: string): Promise<T>;
  loadAssistantSessionEvents?<T>(
    threadId: string,
    options?: AssistantSessionThreadLoadOptions,
  ): Promise<T[]>;
  loadSessionThreadEvents<T>(
    threadId: string,
    options?: AssistantSessionThreadLoadOptions,
  ): Promise<T[]>;
  loadAssistantSessionArtifacts?<T>(threadId: string): Promise<T[]>;
  loadSessionThreadArtifacts<T>(threadId: string): Promise<T[]>;
  showPillShell(): Promise<void>;
  hidePillShell(): Promise<void>;
  showSpotlightShell(): Promise<void>;
  hideSpotlightShell(): Promise<void>;
  showGateShell(): Promise<void>;
  hideGateShell(): Promise<void>;
  showStudioShell(): Promise<void>;
  openStudioView(view: StudioViewTarget): Promise<void>;
  openStudioSessionTarget(sessionId: string): Promise<void>;
  openStudioCapabilityTarget(
    connectorId?: string | null,
    detailSection?: StudioCapabilityDetailSection | null,
  ): Promise<void>;
  openStudioPolicyTarget(connectorId?: string | null): Promise<void>;
  openStudioAssistantWorkbench(
    session: AssistantWorkbenchSession,
  ): Promise<void>;
  activateAssistantWorkbenchSession(
    session: AssistantWorkbenchSession,
  ): Promise<void>;
  openStudioAutopilotIntent(intent: string): Promise<void>;
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
  submitAssistantSessionRuntimePassword?(
    sessionId: string,
    password: string,
  ): Promise<void>;
  submitSessionRuntimePassword(
    sessionId: string,
    password: string,
  ): Promise<void>;
  respondToAssistantSessionGate?(
    input: AssistantSessionGateResponse,
  ): Promise<void>;
  respondToSessionGate(input: AssistantSessionGateResponse): Promise<void>;
  listenAssistantSessionProjection?<TSession, TSessionSummary>(
    handler: (projection: AssistantSessionProjection<TSession, TSessionSummary>) => void,
  ): Promise<() => void>;
  listenSessionProjection<TSession, TSessionSummary>(
    handler: (projection: AssistantSessionProjection<TSession, TSessionSummary>) => void,
  ): Promise<() => void>;
  listenAssistantSessionEvent?<T>(
    eventName: AssistantSessionEventName,
    handler: (payload: T) => void,
  ): Promise<() => void>;
  listenSessionEvent<T>(
    eventName: AssistantSessionEventName,
    handler: (payload: T) => void,
  ): Promise<() => void>;
}

export type AgentSessionEventName = AssistantSessionEventName;
export type AgentSessionProjection<
  TTask = unknown,
  TSessionSummary = unknown,
> = AssistantSessionProjection<TTask, TSessionSummary>;
export type AgentSessionThreadLoadOptions = AssistantSessionThreadLoadOptions;
export type AgentSessionGateResponse = AssistantSessionGateResponse;
export type AgentSessionRuntime = AssistantSessionRuntime;
