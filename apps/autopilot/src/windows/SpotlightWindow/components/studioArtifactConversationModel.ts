import type {
  AgentEvent,
  BuildArtifactSession,
  StudioArtifactSession,
  StudioRendererKind,
  StudioRendererSession,
} from "../../../types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : null;
}

function studioArtifactSessionCandidate(value: unknown): StudioArtifactSession | null {
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

  return value as unknown as StudioArtifactSession;
}

export function extractStudioArtifactSessionFromEvent(
  event: AgentEvent,
): StudioArtifactSession | null {
  const directCandidate = studioArtifactSessionCandidate(event.details);
  if (directCandidate) {
    return directCandidate;
  }

  const nestedCandidate = isRecord(event.details)
    ? studioArtifactSessionCandidate(
        event.details.studioSession ?? event.details.studio_session,
      )
    : null;

  return nestedCandidate ?? null;
}

export interface StudioConversationArtifactEntry {
  key: string;
  sessionId: string;
  artifactId: string;
  title: string;
  summary: string;
  renderer: StudioRendererKind;
  artifactClass: StudioArtifactSession["artifactManifest"]["artifactClass"];
  status: string;
  lifecycleState: StudioArtifactSession["lifecycleState"];
  fileCount: number;
  timestamp: string;
  sourceEventId: string;
  studioSession: StudioArtifactSession;
}

function buildStudioConversationArtifactEntry(
  studioSession: StudioArtifactSession,
  options: {
    sourceEventId: string;
    timestamp: string;
  },
): StudioConversationArtifactEntry {
  return {
    key: `${studioSession.sessionId}:${options.sourceEventId}`,
    sessionId: studioSession.sessionId,
    artifactId: studioSession.artifactManifest.artifactId,
    title: studioSession.title,
    summary: studioSession.summary,
    renderer: studioSession.artifactManifest.renderer,
    artifactClass: studioSession.artifactManifest.artifactClass,
    status: studioSession.verifiedReply.status,
    lifecycleState: studioSession.lifecycleState,
    fileCount: studioSession.artifactManifest.files.length,
    timestamp: options.timestamp,
    sourceEventId: options.sourceEventId,
    studioSession,
  };
}

export function collectStudioConversationArtifacts(
  events: AgentEvent[],
): StudioConversationArtifactEntry[] {
  const seenSessionIds = new Set<string>();
  const ordered = [...events].sort(
    (left, right) =>
      left.timestamp.localeCompare(right.timestamp) ||
      left.step_index - right.step_index ||
      left.event_id.localeCompare(right.event_id),
  );
  const entries: StudioConversationArtifactEntry[] = [];

  for (const event of ordered) {
    const studioSession = extractStudioArtifactSessionFromEvent(event);
    if (!studioSession || studioSession.outcomeRequest.outcomeKind !== "artifact") {
      continue;
    }

    if (seenSessionIds.has(studioSession.sessionId)) {
      continue;
    }
    seenSessionIds.add(studioSession.sessionId);

    entries.push(
      buildStudioConversationArtifactEntry(studioSession, {
        sourceEventId: event.event_id,
        timestamp: event.timestamp,
      }),
    );
  }

  return entries;
}

export function collectAvailableStudioArtifacts(
  events: AgentEvent[],
  activeStudioSession?: StudioArtifactSession | null,
): StudioConversationArtifactEntry[] {
  const bySessionId = new Map<string, StudioConversationArtifactEntry>();

  for (const artifact of collectStudioConversationArtifacts(events)) {
    bySessionId.set(artifact.sessionId, artifact);
  }

  if (activeStudioSession?.outcomeRequest.outcomeKind === "artifact") {
    bySessionId.set(
      activeStudioSession.sessionId,
      buildStudioConversationArtifactEntry(activeStudioSession, {
        sourceEventId: `live:${activeStudioSession.sessionId}`,
        timestamp:
          stringField(activeStudioSession.updatedAt) ??
          stringField(activeStudioSession.createdAt) ??
          new Date().toISOString(),
      }),
    );
  }

  return Array.from(bySessionId.values()).sort(
    (left, right) =>
      right.timestamp.localeCompare(left.timestamp) ||
      right.studioSession.updatedAt.localeCompare(left.studioSession.updatedAt) ||
      right.sessionId.localeCompare(left.sessionId),
  );
}

function mirrorBuildSession(buildSession: BuildArtifactSession): StudioRendererSession {
  return {
    sessionId: buildSession.sessionId,
    studioSessionId: buildSession.studioSessionId,
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

export function deriveRendererSessionForStudioSession(
  studioSession: StudioArtifactSession,
  activeRendererSession?: StudioRendererSession | null,
  activeBuildSession?: BuildArtifactSession | null,
): StudioRendererSession | null {
  if (activeRendererSession?.studioSessionId === studioSession.sessionId) {
    return activeRendererSession;
  }

  if (activeBuildSession?.studioSessionId === studioSession.sessionId) {
    return mirrorBuildSession(activeBuildSession);
  }

  if (
    studioSession.artifactManifest.renderer !== "workspace_surface" ||
    !stringField(studioSession.workspaceRoot)
  ) {
    return null;
  }

  const primaryTab = studioSession.artifactManifest.tabs.find(
    (tab) => tab.id === studioSession.artifactManifest.primaryTab,
  );
  const entryDocument =
    stringField(primaryTab?.filePath) ??
    stringField(studioSession.artifactManifest.files[0]?.path) ??
    "index.html";
  const previewUrl =
    studioSession.artifactManifest.files.find((file) => typeof file.externalUrl === "string")
      ?.externalUrl ?? null;

  return {
    sessionId:
      stringField(studioSession.rendererSessionId) ??
      stringField(studioSession.buildSessionId) ??
      studioSession.sessionId,
    studioSessionId: studioSession.sessionId,
    renderer: "workspace_surface",
    workspaceRoot: studioSession.workspaceRoot!,
    entryDocument,
    previewUrl,
    previewProcessId: null,
    scaffoldRecipeId: null,
    presentationVariantId: null,
    packageManager: null,
    status: studioSession.status,
    verificationStatus: studioSession.verifiedReply.status,
    receipts: [],
    currentWorkerExecution: null,
    currentTab: previewUrl ? "preview" : "workspace",
    availableTabs: previewUrl ? ["preview", "workspace", "evidence"] : ["workspace", "evidence"],
    readyTabs: previewUrl ? ["preview", "workspace", "evidence"] : ["workspace", "evidence"],
    retryCount: 0,
    lastFailureSummary: studioSession.verifiedReply.failure?.message ?? null,
  };
}
