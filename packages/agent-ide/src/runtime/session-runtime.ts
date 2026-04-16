import type {
  AssistantSessionEventName,
  AssistantSessionGateResponse,
  AssistantSessionProjection,
  AssistantSessionRuntime,
  AssistantWorkbenchActivity,
  AssistantWorkbenchSession,
  StudioCapabilityDetailSection,
  StudioViewTarget,
} from "./assistant-session-runtime-types";

let defaultAssistantSessionRuntime: AssistantSessionRuntime | null = null;
let activeAssistantSessionRuntime: AssistantSessionRuntime | null = null;

export function setDefaultAssistantSessionRuntime(
  runtime: AssistantSessionRuntime,
): void {
  const previousDefault = defaultAssistantSessionRuntime;
  defaultAssistantSessionRuntime = runtime;
  if (
    activeAssistantSessionRuntime === null ||
    activeAssistantSessionRuntime === previousDefault
  ) {
    activeAssistantSessionRuntime = runtime;
  }
}

export function setActiveAssistantSessionRuntime(
  runtime: AssistantSessionRuntime | null,
): void {
  activeAssistantSessionRuntime = runtime ?? defaultAssistantSessionRuntime;
}

export function getAssistantSessionRuntime(): AssistantSessionRuntime {
  if (!activeAssistantSessionRuntime) {
    throw new Error("No assistant session runtime configured");
  }
  return activeAssistantSessionRuntime;
}

export function startAssistantSession<T>(intent: string): Promise<T> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.startAssistantSession === "function") {
    return runtime.startAssistantSession<T>(intent);
  }
  return runtime.startSessionTask<T>(intent);
}

export function submitAssistantSessionInput(
  sessionId: string,
  userInput: string,
): Promise<void> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.submitAssistantSessionInput === "function") {
    return runtime.submitAssistantSessionInput(sessionId, userInput);
  }
  return runtime.continueSessionTask(sessionId, userInput);
}

export function dismissAssistantSession(): Promise<void> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.dismissAssistantSession === "function") {
    return runtime.dismissAssistantSession();
  }
  return runtime.dismissSessionTask();
}

export function stopAssistantSession(): Promise<void> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.stopAssistantSession === "function") {
    return runtime.stopAssistantSession();
  }
  return runtime.stopSessionTask();
}

export function getActiveAssistantSession<T>(): Promise<T | null> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.getActiveAssistantSession === "function") {
    return runtime.getActiveAssistantSession<T>();
  }
  return runtime.getCurrentSessionTask<T>();
}

export function listAssistantSessions<T>(): Promise<T[]> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.listAssistantSessions === "function") {
    return runtime.listAssistantSessions<T>();
  }
  return runtime.listSessionHistory<T>();
}

export function getAssistantSessionProjection<TSession, TSessionSummary>(): Promise<
  AssistantSessionProjection<TSession, TSessionSummary>
> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.getAssistantSessionProjection === "function") {
    return runtime.getAssistantSessionProjection<TSession, TSessionSummary>();
  }
  return runtime.getSessionProjection<TSession, TSessionSummary>();
}

export function loadAssistantSession<T>(sessionId: string): Promise<T> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.loadAssistantSession === "function") {
    return runtime.loadAssistantSession<T>(sessionId);
  }
  return runtime.loadSessionTask<T>(sessionId);
}

export function loadAssistantSessionEvents<T>(
  threadId: string,
  limit?: number,
  cursor?: number,
): Promise<T[]> {
  const runtime = getAssistantSessionRuntime();
  const options = { limit, cursor };
  if (typeof runtime.loadAssistantSessionEvents === "function") {
    return runtime.loadAssistantSessionEvents<T>(threadId, options);
  }
  return runtime.loadSessionThreadEvents<T>(threadId, options);
}

export function loadAssistantSessionArtifacts<T>(
  threadId: string,
): Promise<T[]> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.loadAssistantSessionArtifacts === "function") {
    return runtime.loadAssistantSessionArtifacts<T>(threadId);
  }
  return runtime.loadSessionThreadArtifacts<T>(threadId);
}

export function showPillShell(): Promise<void> {
  return getAssistantSessionRuntime().showPillShell();
}

export function hidePillShell(): Promise<void> {
  return getAssistantSessionRuntime().hidePillShell();
}

export function showSpotlightShell(): Promise<void> {
  return getAssistantSessionRuntime().showSpotlightShell();
}

export function hideSpotlightShell(): Promise<void> {
  return getAssistantSessionRuntime().hideSpotlightShell();
}

export function showGateShell(): Promise<void> {
  return getAssistantSessionRuntime().showGateShell();
}

export function hideGateShell(): Promise<void> {
  return getAssistantSessionRuntime().hideGateShell();
}

export function showStudioShell(): Promise<void> {
  return getAssistantSessionRuntime().showStudioShell();
}

export function openStudioShellView(view: StudioViewTarget): Promise<void> {
  return getAssistantSessionRuntime().openStudioView(view);
}

export function openStudioSessionTarget(sessionId: string): Promise<void> {
  return getAssistantSessionRuntime().openStudioSessionTarget(sessionId);
}

export function openStudioCapabilityTarget(
  connectorId?: string | null,
  detailSection?: StudioCapabilityDetailSection | null,
): Promise<void> {
  return getAssistantSessionRuntime().openStudioCapabilityTarget(
    connectorId,
    detailSection,
  );
}

export function openStudioPolicyTarget(
  connectorId?: string | null,
): Promise<void> {
  return getAssistantSessionRuntime().openStudioPolicyTarget(connectorId);
}

export function openStudioAssistantWorkbench(
  session: AssistantWorkbenchSession,
): Promise<void> {
  return getAssistantSessionRuntime().openStudioAssistantWorkbench(session);
}

export function activateAssistantWorkbenchSession(
  session: AssistantWorkbenchSession,
): Promise<void> {
  return getAssistantSessionRuntime().activateAssistantWorkbenchSession(
    session,
  );
}

export function getActiveAssistantWorkbenchSession(): Promise<AssistantWorkbenchSession | null> {
  return getAssistantSessionRuntime().getActiveAssistantWorkbenchSession();
}

export function openStudioAutopilotIntent(intent: string): Promise<void> {
  return getAssistantSessionRuntime().openStudioAutopilotIntent(intent);
}

export function listenAssistantWorkbenchSession(
  handler: (session: AssistantWorkbenchSession) => void,
): Promise<() => void> {
  return getAssistantSessionRuntime().listenAssistantWorkbenchSession(handler);
}

export function reportAssistantWorkbenchActivity(
  activity: AssistantWorkbenchActivity,
): Promise<void> {
  return getAssistantSessionRuntime().reportAssistantWorkbenchActivity(activity);
}

export function getRecentAssistantWorkbenchActivities(
  limit?: number,
): Promise<AssistantWorkbenchActivity[]> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.getRecentAssistantWorkbenchActivities === "function") {
    return runtime.getRecentAssistantWorkbenchActivities(limit);
  }
  return Promise.resolve([]);
}

export function listenAssistantWorkbenchActivity(
  handler: (activity: AssistantWorkbenchActivity) => void,
): Promise<() => void> {
  return getAssistantSessionRuntime().listenAssistantWorkbenchActivity(handler);
}

export function submitAssistantSessionRuntimePassword(
  sessionId: string,
  password: string,
): Promise<void> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.submitAssistantSessionRuntimePassword === "function") {
    return runtime.submitAssistantSessionRuntimePassword(sessionId, password);
  }
  return runtime.submitSessionRuntimePassword(sessionId, password);
}

export function respondToAssistantSessionGate(
  input: AssistantSessionGateResponse,
): Promise<void> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.respondToAssistantSessionGate === "function") {
    return runtime.respondToAssistantSessionGate(input);
  }
  return runtime.respondToSessionGate(input);
}

export function listenAssistantSessionProjection<TSession, TSessionSummary>(
  handler: (
    projection: AssistantSessionProjection<TSession, TSessionSummary>,
  ) => void,
): Promise<() => void> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.listenAssistantSessionProjection === "function") {
    return runtime.listenAssistantSessionProjection<TSession, TSessionSummary>(
      handler,
    );
  }
  return runtime.listenSessionProjection<TSession, TSessionSummary>(handler);
}

export function listenAssistantSessionEvent<T>(
  eventName: AssistantSessionEventName,
  handler: (payload: T) => void,
): Promise<() => void> {
  const runtime = getAssistantSessionRuntime();
  if (typeof runtime.listenAssistantSessionEvent === "function") {
    return runtime.listenAssistantSessionEvent<T>(eventName, handler);
  }
  return runtime.listenSessionEvent<T>(eventName, handler);
}

export const setDefaultSessionRuntime = setDefaultAssistantSessionRuntime;
export const setSessionRuntime = setActiveAssistantSessionRuntime;
export const getSessionRuntime = getAssistantSessionRuntime;
export const startSessionTask = startAssistantSession;
export const continueSessionTask = submitAssistantSessionInput;
export const dismissSessionTask = dismissAssistantSession;
export const stopSessionTask = stopAssistantSession;
export const getCurrentSessionTask = getActiveAssistantSession;
export const listSessionHistory = listAssistantSessions;
export const getSessionProjection = getAssistantSessionProjection;
export const loadSessionTask = loadAssistantSession;
export const loadSessionThreadEvents = loadAssistantSessionEvents;
export const loadSessionThreadArtifacts = loadAssistantSessionArtifacts;
export const submitSessionRuntimePassword =
  submitAssistantSessionRuntimePassword;
export const respondToSessionGate = respondToAssistantSessionGate;
export const listenSessionProjection = listenAssistantSessionProjection;
export const listenSessionEvent = listenAssistantSessionEvent;
