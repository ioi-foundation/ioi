import type {
  AssistantSessionEventName,
  AssistantSessionGateResponse,
  AssistantSessionProjection,
  AssistantSessionRuntime,
  AssistantWorkbenchActivity,
  AssistantWorkbenchSession,
  ChatCapabilityDetailSection,
  ChatViewTarget,
} from "./assistant-session-runtime-types";

let defaultSessionRuntimeInstance: AssistantSessionRuntime | null = null;
let activeSessionRuntimeInstance: AssistantSessionRuntime | null = null;

export function setDefaultSessionRuntime(
  runtime: AssistantSessionRuntime,
): void {
  const previousDefault = defaultSessionRuntimeInstance;
  defaultSessionRuntimeInstance = runtime;
  if (
    activeSessionRuntimeInstance === null ||
    activeSessionRuntimeInstance === previousDefault
  ) {
    activeSessionRuntimeInstance = runtime;
  }
}

export function setSessionRuntime(
  runtime: AssistantSessionRuntime | null,
): void {
  activeSessionRuntimeInstance = runtime ?? defaultSessionRuntimeInstance;
}

export function getSessionRuntime(): AssistantSessionRuntime {
  if (!activeSessionRuntimeInstance) {
    throw new Error("No session runtime configured");
  }
  return activeSessionRuntimeInstance;
}

export function startSessionTask<T>(intent: string): Promise<T> {
  return getSessionRuntime().startSessionTask<T>(intent);
}

export function continueSessionTask(
  sessionId: string,
  userInput: string,
): Promise<void> {
  return getSessionRuntime().continueSessionTask(sessionId, userInput);
}

export function dismissSessionTask(): Promise<void> {
  return getSessionRuntime().dismissSessionTask();
}

export function stopSessionTask(): Promise<void> {
  return getSessionRuntime().stopSessionTask();
}

export function getCurrentSessionTask<T>(): Promise<T | null> {
  return getSessionRuntime().getCurrentSessionTask<T>();
}

export function listSessionHistory<T>(): Promise<T[]> {
  return getSessionRuntime().listSessionHistory<T>();
}

export function getSessionProjection<TSession, TSessionSummary>(): Promise<
  AssistantSessionProjection<TSession, TSessionSummary>
> {
  return getSessionRuntime().getSessionProjection<TSession, TSessionSummary>();
}

export function loadSessionTask<T>(sessionId: string): Promise<T> {
  return getSessionRuntime().loadSessionTask<T>(sessionId);
}

export function loadSessionThreadEvents<T>(
  threadId: string,
  limit?: number,
  cursor?: number,
): Promise<T[]> {
  return getSessionRuntime().loadSessionThreadEvents<T>(threadId, {
    limit,
    cursor,
  });
}

export function loadSessionThreadArtifacts<T>(
  threadId: string,
): Promise<T[]> {
  return getSessionRuntime().loadSessionThreadArtifacts<T>(threadId);
}

export function showPillShell(): Promise<void> {
  return getSessionRuntime().showPillShell();
}

export function hidePillShell(): Promise<void> {
  return getSessionRuntime().hidePillShell();
}

export function showChatSessionShell(): Promise<void> {
  return getSessionRuntime().showChatSessionShell();
}

export function hideChatSessionShell(): Promise<void> {
  return getSessionRuntime().hideChatSessionShell();
}

export function showChatShell(): Promise<void> {
  return getSessionRuntime().showChatShell();
}

export function openChatShellView(view: ChatViewTarget): Promise<void> {
  return getSessionRuntime().openChatView(view);
}

export function openChatSessionTarget(sessionId: string): Promise<void> {
  return getSessionRuntime().openChatSessionTarget(sessionId);
}

export function openChatCapabilityTarget(
  connectorId?: string | null,
  detailSection?: ChatCapabilityDetailSection | null,
): Promise<void> {
  return getSessionRuntime().openChatCapabilityTarget(
    connectorId,
    detailSection,
  );
}

export function openChatPolicyTarget(
  connectorId?: string | null,
): Promise<void> {
  return getSessionRuntime().openChatPolicyTarget(connectorId);
}

export function openChatAssistantWorkbench(
  session: AssistantWorkbenchSession,
): Promise<void> {
  return getSessionRuntime().openChatAssistantWorkbench(session);
}

export function activateAssistantWorkbenchSession(
  session: AssistantWorkbenchSession,
): Promise<void> {
  return getSessionRuntime().activateAssistantWorkbenchSession(session);
}

export function getActiveAssistantWorkbenchSession(): Promise<AssistantWorkbenchSession | null> {
  return getSessionRuntime().getActiveAssistantWorkbenchSession();
}

export function openChatHypervisorIntent(intent: string): Promise<void> {
  return getSessionRuntime().openChatHypervisorIntent(intent);
}

export function listenAssistantWorkbenchSession(
  handler: (session: AssistantWorkbenchSession) => void,
): Promise<() => void> {
  return getSessionRuntime().listenAssistantWorkbenchSession(handler);
}

export function reportAssistantWorkbenchActivity(
  activity: AssistantWorkbenchActivity,
): Promise<void> {
  return getSessionRuntime().reportAssistantWorkbenchActivity(activity);
}

export function getRecentAssistantWorkbenchActivities(
  limit?: number,
): Promise<AssistantWorkbenchActivity[]> {
  const runtime = getSessionRuntime();
  if (typeof runtime.getRecentAssistantWorkbenchActivities === "function") {
    return runtime.getRecentAssistantWorkbenchActivities(limit);
  }
  return Promise.resolve([]);
}

export function listenAssistantWorkbenchActivity(
  handler: (activity: AssistantWorkbenchActivity) => void,
): Promise<() => void> {
  return getSessionRuntime().listenAssistantWorkbenchActivity(handler);
}

export function submitSessionRuntimePassword(
  sessionId: string,
  password: string,
): Promise<void> {
  return getSessionRuntime().submitSessionRuntimePassword(sessionId, password);
}

export function respondToSessionGate(
  input: AssistantSessionGateResponse,
): Promise<void> {
  return getSessionRuntime().respondToSessionGate(input);
}

export function listenSessionProjection<TSession, TSessionSummary>(
  handler: (
    projection: AssistantSessionProjection<TSession, TSessionSummary>,
  ) => void,
): Promise<() => void> {
  return getSessionRuntime().listenSessionProjection<TSession, TSessionSummary>(
    handler,
  );
}

export function listenSessionEvent<T>(
  eventName: AssistantSessionEventName,
  handler: (payload: T) => void,
): Promise<() => void> {
  return getSessionRuntime().listenSessionEvent<T>(eventName, handler);
}
