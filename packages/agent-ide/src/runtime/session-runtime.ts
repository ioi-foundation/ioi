import type {
  AgentSessionEventName,
  AgentSessionGateResponse,
  AgentSessionProjection,
  AgentSessionRuntime,
  AssistantWorkbenchActivity,
  AssistantWorkbenchSession,
  StudioCapabilityDetailSection,
  StudioViewTarget,
} from "./agent-runtime";

let defaultSessionRuntime: AgentSessionRuntime | null = null;
let activeSessionRuntime: AgentSessionRuntime | null = null;

export function setDefaultSessionRuntime(runtime: AgentSessionRuntime): void {
  const previousDefault = defaultSessionRuntime;
  defaultSessionRuntime = runtime;
  if (activeSessionRuntime === null || activeSessionRuntime === previousDefault) {
    activeSessionRuntime = runtime;
  }
}

export function setSessionRuntime(runtime: AgentSessionRuntime | null): void {
  activeSessionRuntime = runtime ?? defaultSessionRuntime;
}

export function getSessionRuntime(): AgentSessionRuntime {
  if (!activeSessionRuntime) {
    throw new Error("No session runtime configured");
  }
  return activeSessionRuntime;
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

export function getSessionProjection<TTask, TSessionSummary>(): Promise<
  AgentSessionProjection<TTask, TSessionSummary>
> {
  return getSessionRuntime().getSessionProjection<TTask, TSessionSummary>();
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

export function loadSessionThreadArtifacts<T>(threadId: string): Promise<T[]> {
  return getSessionRuntime().loadSessionThreadArtifacts<T>(threadId);
}

export function showPillShell(): Promise<void> {
  return getSessionRuntime().showPillShell();
}

export function hidePillShell(): Promise<void> {
  return getSessionRuntime().hidePillShell();
}

export function showSpotlightShell(): Promise<void> {
  return getSessionRuntime().showSpotlightShell();
}

export function hideSpotlightShell(): Promise<void> {
  return getSessionRuntime().hideSpotlightShell();
}

export function showGateShell(): Promise<void> {
  return getSessionRuntime().showGateShell();
}

export function hideGateShell(): Promise<void> {
  return getSessionRuntime().hideGateShell();
}

export function showStudioShell(): Promise<void> {
  return getSessionRuntime().showStudioShell();
}

export function openStudioShellView(view: StudioViewTarget): Promise<void> {
  return getSessionRuntime().openStudioView(view);
}

export function openStudioSessionTarget(sessionId: string): Promise<void> {
  return getSessionRuntime().openStudioSessionTarget(sessionId);
}

export function openStudioCapabilityTarget(
  connectorId?: string | null,
  detailSection?: StudioCapabilityDetailSection | null,
): Promise<void> {
  return getSessionRuntime().openStudioCapabilityTarget(
    connectorId,
    detailSection,
  );
}

export function openStudioPolicyTarget(
  connectorId?: string | null,
): Promise<void> {
  return getSessionRuntime().openStudioPolicyTarget(connectorId);
}

export function openStudioAssistantWorkbench(
  session: AssistantWorkbenchSession,
): Promise<void> {
  return getSessionRuntime().openStudioAssistantWorkbench(session);
}

export function activateAssistantWorkbenchSession(
  session: AssistantWorkbenchSession,
): Promise<void> {
  return getSessionRuntime().activateAssistantWorkbenchSession(session);
}

export function getActiveAssistantWorkbenchSession(): Promise<AssistantWorkbenchSession | null> {
  return getSessionRuntime().getActiveAssistantWorkbenchSession();
}

export function openStudioAutopilotIntent(intent: string): Promise<void> {
  return getSessionRuntime().openStudioAutopilotIntent(intent);
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
  input: AgentSessionGateResponse,
): Promise<void> {
  return getSessionRuntime().respondToSessionGate(input);
}

export function listenSessionProjection<TTask, TSessionSummary>(
  handler: (projection: AgentSessionProjection<TTask, TSessionSummary>) => void,
): Promise<() => void> {
  return getSessionRuntime().listenSessionProjection<TTask, TSessionSummary>(
    handler,
  );
}

export function listenSessionEvent<T>(
  eventName: AgentSessionEventName,
  handler: (payload: T) => void,
): Promise<() => void> {
  return getSessionRuntime().listenSessionEvent<T>(eventName, handler);
}
