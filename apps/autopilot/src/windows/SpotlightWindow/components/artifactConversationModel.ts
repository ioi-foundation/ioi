import type {
  AgentEvent,
  BuildArtifactSession,
  ChatArtifactSession,
  ChatRendererKind,
  ChatRendererSession,
} from "../../../types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function artifactSessionCandidate(value: unknown): ChatArtifactSession | null {
  if (!isRecord(value)) {
    return null;
  }

  const sessionId = stringField(value.sessionId);
  const title = stringField(value.title);
  const artifactManifest = isRecord(value.artifactManifest) ? value.artifactManifest : null;
  const verifiedReply = isRecord(value.verifiedReply) ? value.verifiedReply : null;
  const outcomeRequest = isRecord(value.outcomeRequest) ? value.outcomeRequest : null;
  const artifactId = artifactManifest ? stringField(artifactManifest.artifactId) : null;

  if (!sessionId || !title || !artifactManifest || !verifiedReply || !outcomeRequest || !artifactId) {
    return null;
  }

  return value as unknown as ChatArtifactSession;
}

export function extractChatArtifactSessionFromEvent(
  event: AgentEvent,
): ChatArtifactSession | null {
  const directCandidate = artifactSessionCandidate(event.details);
  if (directCandidate) {
    return directCandidate;
  }

  const nestedCandidate = isRecord(event.details)
    ? artifactSessionCandidate(
        event.details.chatSession ?? event.details.chat_session,
      )
    : null;

  return nestedCandidate ?? null;
}

export interface ConversationArtifactEntry {
  key: string;
  sessionId: string;
  artifactId: string;
  title: string;
  summary: string;
  renderer: ChatRendererKind;
  artifactClass: ChatArtifactSession["artifactManifest"]["artifactClass"];
  status: string;
  lifecycleState: ChatArtifactSession["lifecycleState"];
  fileCount: number;
  timestamp: string;
  sourceEventId: string;
  chatSession: ChatArtifactSession;
}

function buildConversationArtifactEntry(
  chatSession: ChatArtifactSession,
  options: {
    sourceEventId: string;
    timestamp: string;
  },
): ConversationArtifactEntry {
  return {
    key: `${chatSession.sessionId}:${options.sourceEventId}`,
    sessionId: chatSession.sessionId,
    artifactId: chatSession.artifactManifest.artifactId,
    title: chatSession.title,
    summary: chatSession.summary,
    renderer: chatSession.artifactManifest.renderer,
    artifactClass: chatSession.artifactManifest.artifactClass,
    status: chatSession.verifiedReply.status,
    lifecycleState: chatSession.lifecycleState,
    fileCount: chatSession.artifactManifest.files.length,
    timestamp: options.timestamp,
    sourceEventId: options.sourceEventId,
    chatSession,
  };
}

export function artifactSessionIsPresentable(
  chatSession: ChatArtifactSession,
): boolean {
  const verificationStatus = String(
    chatSession.artifactManifest.verification.status || "",
  )
    .trim()
    .toLowerCase();
  const lifecycleState = String(
    chatSession.artifactManifest.verification.lifecycleState ||
      chatSession.lifecycleState ||
      chatSession.verifiedReply.lifecycleState ||
      chatSession.status ||
      "",
  )
    .trim()
    .toLowerCase();

  if (
    verificationStatus === "blocked" ||
    verificationStatus === "failed" ||
    lifecycleState === "blocked" ||
    lifecycleState === "failed"
  ) {
    return true;
  }

  if (verificationStatus === "ready" || verificationStatus === "partial") {
    return chatSession.artifactManifest.files.length > 0;
  }

  if (chatSession.status.trim().toLowerCase() === "ready") {
    return chatSession.artifactManifest.files.length > 0;
  }

  return false;
}

export function collectConversationArtifacts(
  events: AgentEvent[],
): ConversationArtifactEntry[] {
  const seenSessionIds = new Set<string>();
  const ordered = [...events].sort(
    (left, right) =>
      left.timestamp.localeCompare(right.timestamp) ||
      left.step_index - right.step_index ||
      left.event_id.localeCompare(right.event_id),
  );
  const entries: ConversationArtifactEntry[] = [];

  for (const event of ordered) {
    const chatSession = extractChatArtifactSessionFromEvent(event);
    if (!chatSession || chatSession.outcomeRequest.outcomeKind !== "artifact") {
      continue;
    }

    if (seenSessionIds.has(chatSession.sessionId)) {
      continue;
    }
    seenSessionIds.add(chatSession.sessionId);

    entries.push(
      buildConversationArtifactEntry(chatSession, {
        sourceEventId: event.event_id,
        timestamp: event.timestamp,
      }),
    );
  }

  return entries;
}

export function collectConversationArtifactsForTurn(
  allEvents: AgentEvent[],
  windowEvents: AgentEvent[],
  turnId: string | null,
  activeChatSession?: ChatArtifactSession | null,
): ConversationArtifactEntry[] {
  if (!turnId) {
    return [];
  }

  const bySessionId = new Map<string, ConversationArtifactEntry>();
  const windowEventIds = new Set(windowEvents.map((event) => event.event_id));
  const ordered = [...allEvents].sort(
    (left, right) =>
      left.timestamp.localeCompare(right.timestamp) ||
      left.step_index - right.step_index ||
      left.event_id.localeCompare(right.event_id),
  );

  for (const event of ordered) {
    const chatSession = extractChatArtifactSessionFromEvent(event);
    if (!chatSession || chatSession.outcomeRequest.outcomeKind !== "artifact") {
      continue;
    }

    const sessionTurnId = stringField(chatSession.originPromptEventId);
    const belongsToTurn = sessionTurnId
      ? sessionTurnId === turnId
      : windowEventIds.has(event.event_id);
    if (
      !belongsToTurn ||
      bySessionId.has(chatSession.sessionId) ||
      !artifactSessionIsPresentable(chatSession)
    ) {
      continue;
    }

    bySessionId.set(
      chatSession.sessionId,
      buildConversationArtifactEntry(chatSession, {
        sourceEventId: event.event_id,
        timestamp: event.timestamp,
      }),
    );
  }

  if (
    activeChatSession?.outcomeRequest.outcomeKind === "artifact" &&
    stringField(activeChatSession.originPromptEventId) === turnId &&
    artifactSessionIsPresentable(activeChatSession)
  ) {
    bySessionId.set(
      activeChatSession.sessionId,
      buildConversationArtifactEntry(activeChatSession, {
        sourceEventId: `live:${activeChatSession.sessionId}`,
        timestamp:
          stringField(activeChatSession.updatedAt) ??
          stringField(activeChatSession.createdAt) ??
          new Date().toISOString(),
      }),
    );
  }

  return Array.from(bySessionId.values()).sort(
    (left, right) =>
      left.timestamp.localeCompare(right.timestamp) ||
      left.sessionId.localeCompare(right.sessionId),
  );
}

export function collectAvailableArtifacts(
  events: AgentEvent[],
  activeChatSession?: ChatArtifactSession | null,
): ConversationArtifactEntry[] {
  const bySessionId = new Map<string, ConversationArtifactEntry>();

  for (const artifact of collectConversationArtifacts(events)) {
    bySessionId.set(artifact.sessionId, artifact);
  }

  if (activeChatSession?.outcomeRequest.outcomeKind === "artifact") {
    bySessionId.set(
      activeChatSession.sessionId,
      buildConversationArtifactEntry(activeChatSession, {
        sourceEventId: `live:${activeChatSession.sessionId}`,
        timestamp:
          stringField(activeChatSession.updatedAt) ??
          stringField(activeChatSession.createdAt) ??
          new Date().toISOString(),
      }),
    );
  }

  return Array.from(bySessionId.values()).sort(
    (left, right) =>
      right.timestamp.localeCompare(left.timestamp) ||
      right.chatSession.updatedAt.localeCompare(left.chatSession.updatedAt) ||
      right.sessionId.localeCompare(left.sessionId),
  );
}

function mirrorBuildSession(buildSession: BuildArtifactSession): ChatRendererSession {
  return {
    sessionId: buildSession.sessionId,
    chatSessionId: buildSession.chatSessionId,
    renderer: "workspace_surface",
    workspaceRoot: buildSession.workspaceRoot,
    entryDocument: buildSession.entryDocument,
    previewUrl: buildSession.previewUrl,
    previewProcessId: buildSession.previewProcessId,
    scaffoldRecipeId: buildSession.scaffoldRecipeId,
    presentationVariantId: buildSession.presentationVariantId,
    packageManager: buildSession.packageManager,
    status: buildSession.buildStatus,
    verificationStatus: buildSession.verificationStatus,
    receipts: buildSession.receipts,
    currentWorkerExecution: buildSession.currentWorkerExecution,
    currentTab: buildSession.readyLenses.includes("preview") ? "preview" : "workspace",
    availableTabs: ["preview", "workspace", "evidence"],
    readyTabs: buildSession.readyLenses.includes("preview")
      ? ["preview", "workspace", "evidence"]
      : ["workspace", "evidence"],
    retryCount: buildSession.retryCount,
    lastFailureSummary: buildSession.lastFailureSummary,
  };
}

export function deriveRendererSessionForChatSession(
  chatSession: ChatArtifactSession,
  activeRendererSession?: ChatRendererSession | null,
  activeBuildSession?: BuildArtifactSession | null,
): ChatRendererSession | null {
  if (activeRendererSession?.chatSessionId === chatSession.sessionId) {
    return activeRendererSession;
  }

  if (activeBuildSession?.chatSessionId === chatSession.sessionId) {
    return mirrorBuildSession(activeBuildSession);
  }

  if (
    chatSession.artifactManifest.renderer !== "workspace_surface" ||
    !stringField(chatSession.workspaceRoot)
  ) {
    return null;
  }

  const primaryTab = chatSession.artifactManifest.tabs.find(
    (tab) => tab.id === chatSession.artifactManifest.primaryTab,
  );
  const entryDocument =
    stringField(primaryTab?.filePath) ??
    stringField(chatSession.artifactManifest.files[0]?.path) ??
    "index.html";
  const previewUrl =
    chatSession.artifactManifest.files.find((file) => typeof file.externalUrl === "string")
      ?.externalUrl ?? null;

  return {
    sessionId:
      stringField(chatSession.rendererSessionId) ??
      stringField(chatSession.buildSessionId) ??
      chatSession.sessionId,
    chatSessionId: chatSession.sessionId,
    renderer: "workspace_surface",
    workspaceRoot: chatSession.workspaceRoot!,
    entryDocument,
    previewUrl,
    previewProcessId: null,
    scaffoldRecipeId: null,
    presentationVariantId: null,
    packageManager: null,
    status: chatSession.status,
    verificationStatus: chatSession.verifiedReply.status,
    receipts: [],
    currentWorkerExecution: null,
    currentTab: previewUrl ? "preview" : "workspace",
    availableTabs: previewUrl ? ["preview", "workspace", "evidence"] : ["workspace", "evidence"],
    readyTabs: previewUrl ? ["preview", "workspace", "evidence"] : ["workspace", "evidence"],
    retryCount: 0,
    lastFailureSummary: chatSession.verifiedReply.failure?.message ?? null,
  };
}
