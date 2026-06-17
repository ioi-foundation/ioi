export interface SessionIdentityLike {
  id?: string | null;
  session_id?: string | null;
  sessionId?: string | null;
}

export interface SessionCredentialRequestLike {
  kind?: string | null;
}

export interface SessionClarificationRequestLike {
  kind?: string | null;
}

export interface SessionBackgroundTaskLike {
  can_stop?: boolean | null;
  canStop?: boolean | null;
}

export interface SessionProgressLike extends SessionIdentityLike {
  phase?: string | null;
  current_step?: string | null;
  currentStep?: string | null;
  pending_request_hash?: unknown;
  pendingRequestHash?: unknown;
  gate_info?: unknown;
  gateInfo?: unknown;
  credential_request?: SessionCredentialRequestLike | null;
  credentialRequest?: SessionCredentialRequestLike | null;
  clarification_request?: SessionClarificationRequestLike | null;
  clarificationRequest?: SessionClarificationRequestLike | null;
  background_tasks?: SessionBackgroundTaskLike[] | null;
  backgroundTasks?: SessionBackgroundTaskLike[] | null;
}

export interface SessionSummaryLike extends SessionIdentityLike {
  title: string;
  timestamp: number;
  phase?: string | null;
  current_step?: string | null;
  currentStep?: string | null;
  resume_hint?: string | null;
  resumeHint?: string | null;
  workspace_root?: string | null;
  workspaceRoot?: string | null;
}

function normalizedStep(step?: string | null): string {
  return (step || "").trim().toLowerCase();
}

export function getSessionId(session: unknown): string | null {
  if (!session || typeof session !== "object") {
    return null;
  }

  const value = session as SessionIdentityLike;
  const sessionId = value.sessionId ?? value.session_id ?? value.id ?? null;
  const trimmed = sessionId?.trim();
  return trimmed ? trimmed : null;
}

export function getSessionStepText(session: {
  current_step?: string | null;
  currentStep?: string | null;
}): string {
  return session.currentStep ?? session.current_step ?? "";
}

export function isWaitingForClarificationStep(step?: string | null): boolean {
  const lowered = normalizedStep(step);
  return (
    lowered.includes("waiting for clarification") ||
    lowered.includes("waiting for intent clarification") ||
    lowered.includes("wait_for_clarification")
  );
}

export function isWaitingForSudoStep(step?: string | null): boolean {
  return normalizedStep(step).includes("waiting for sudo password");
}

export function shouldRetainSessionOnMissingProjection(
  session: unknown,
): boolean {
  if (!session || typeof session !== "object") {
    return false;
  }

  const current = session as SessionProgressLike;
  const phase = typeof current.phase === "string" ? current.phase : null;
  const currentStep = normalizedStep(getSessionStepText(current));
  const backgroundTasks = current.backgroundTasks ?? current.background_tasks;
  const hasBackgroundStop =
    Array.isArray(backgroundTasks) &&
    backgroundTasks.some(
      (entry) => Boolean(entry?.canStop) || Boolean(entry?.can_stop),
    );
  const credentialRequest =
    current.credentialRequest ?? current.credential_request ?? null;
  const clarificationRequest =
    current.clarificationRequest ?? current.clarification_request ?? null;
  const pendingRequestHash =
    current.pendingRequestHash ?? current.pending_request_hash ?? null;
  const gateInfo = current.gateInfo ?? current.gate_info ?? null;

  const hasLiveBlocker =
    Boolean(credentialRequest) ||
    Boolean(clarificationRequest) ||
    Boolean(pendingRequestHash) ||
    Boolean(gateInfo) ||
    phase === "Gate";

  return (
    hasLiveBlocker ||
    phase === "Running" ||
    hasBackgroundStop ||
    currentStep.includes("waiting for") ||
    currentStep.includes("initializing") ||
    currentStep.includes("routing the request")
  );
}

export function sessionSummaryLooksLive(session: SessionSummaryLike): boolean {
  const phase = (session.phase ?? "").trim().toLowerCase();
  const currentStep = normalizedStep(getSessionStepText(session));
  return (
    phase === "running" ||
    phase === "gate" ||
    currentStep.includes("waiting for") ||
    currentStep.includes("initializing") ||
    currentStep.includes("routing the request") ||
    currentStep.includes("sending message")
  );
}

export function normalizeSessionSummary(
  value: unknown,
): SessionSummaryLike | null {
  if (!value || typeof value !== "object") {
    return null;
  }

  const candidate = value as SessionSummaryLike;
  const sessionId = getSessionId(candidate);
  const title =
    typeof candidate.title === "string" ? candidate.title.trim() : "";
  const timestamp =
    typeof candidate.timestamp === "number" ? candidate.timestamp : 0;

  if (!sessionId || !title || timestamp <= 0) {
    return null;
  }

  return {
    id: candidate.id ?? null,
    session_id: candidate.session_id ?? sessionId,
    sessionId: candidate.sessionId ?? sessionId,
    title,
    timestamp,
    phase:
      typeof candidate.phase === "string" ? candidate.phase : null,
    current_step:
      typeof candidate.current_step === "string"
        ? candidate.current_step
        : null,
    currentStep:
      typeof candidate.currentStep === "string"
        ? candidate.currentStep
        : null,
    resume_hint:
      typeof candidate.resume_hint === "string"
        ? candidate.resume_hint
        : null,
    resumeHint:
      typeof candidate.resumeHint === "string"
        ? candidate.resumeHint
        : null,
    workspace_root:
      typeof candidate.workspace_root === "string"
        ? candidate.workspace_root
        : null,
    workspaceRoot:
      typeof candidate.workspaceRoot === "string"
        ? candidate.workspaceRoot
        : null,
  };
}
