import type { WorkspaceActivityEntry } from "@ioi/workspace-substrate";

import type {
  AgentEvent,
  AgentTask,
  BuildArtifactSession,
  ChatArtifactManifest,
  ChatArtifactManifestFile,
  ChatArtifactPipelineStep,
  ChatArtifactSwarmExecutionSummary,
  ChatRendererSession,
} from "../../../types";
import { formatRuntimeStatusLabel } from "../../../services/runtimeInspection";
import type { ChatArtifactStageMode } from "./chatArtifactSurfaceModel";

export interface ChatArtifactSurfaceProps {
  task: AgentTask | null;
  events?: AgentEvent[];
  selectedChatSessionId?: string | null;
  onSelectChatSession: (chatSessionId: string | null) => void;
  onSeedIntent: (intent: string) => void;
  onCollapse?: () => void;
}

export interface SurfaceStageHeaderProps {
  manifest: ChatArtifactManifest;
  title: string;
  stageKicker?: string;
  activePath: string | null;
  copyText?: string | null;
  copyPath?: string | null;
  rendererLabel: string;
  swarmExecution?: ChatArtifactSwarmExecutionSummary | null;
  retrying: boolean;
  stageMode: ChatArtifactStageMode;
  evidenceOpen: boolean;
  showStageModes?: boolean;
  onSelectStageMode: (mode: ChatArtifactStageMode) => void;
  onToggleEvidence: () => void;
  onRetry: (() => void) | null;
  onBrowseArtifacts?: (() => void) | null;
  onCollapse?: (() => void) | null;
}

export interface ArtifactEvidencePanelProps {
  manifest: ChatArtifactManifest;
  chatSession: NonNullable<AgentTask["chat_session"]>;
  pipelineSteps: ChatArtifactPipelineStep[];
  notes: string[];
  evidence: string[];
  receipts?: BuildArtifactSession["receipts"];
  workspaceActivity?: WorkspaceActivityEntry[];
  onOpenArtifact?: (artifactId: string) => void;
  onOpenEvidenceSession?: (sessionId: string) => void;
}

export interface ArtifactRevisionComparison {
  baseRevisionId: string;
  targetRevisionId: string;
  baseBranchLabel: string;
  targetBranchLabel: string;
  changedPaths: string[];
  summary: string;
  sameRenderer: boolean;
  sameTitle: boolean;
}

export interface LogicalArtifactSurfaceProps {
  manifest: ChatArtifactManifest;
  chatSession: NonNullable<AgentTask["chat_session"]>;
  rendererSession: ChatRendererSession | null;
  retrying: boolean;
  onRetry: (() => void) | null;
  onBrowseArtifacts?: (() => void) | null;
  onCollapse?: (() => void) | null;
  onSeedIntent: (intent: string) => void;
}

export interface WorkspaceArtifactSurfaceProps {
  manifest: ChatArtifactManifest;
  chatSession: NonNullable<AgentTask["chat_session"]>;
  rendererSession: ChatRendererSession;
  retrying: boolean;
  onRetry: (() => void) | null;
  onBrowseArtifacts?: (() => void) | null;
  onCollapse?: (() => void) | null;
  onSeedIntent: (intent: string) => void;
}

export function formatStatusLabel(status: string | null | undefined): string {
  if (!status) {
    return "Pending";
  }
  return formatRuntimeStatusLabel(status);
}

function formatRendererLabel(renderer: string): string {
  return renderer
    .split(/[-_]/)
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

export function displayRendererLabel(renderer: string): string {
  const labels: Record<string, string> = {
    markdown: "Markdown",
    html_iframe: "HTML iframe",
    jsx_sandbox: "JSX sandbox",
    svg: "SVG",
    mermaid: "Mermaid",
    pdf_embed: "PDF embed",
    download_card: "Download card",
    workspace_surface: "Workspace surface",
    bundle_manifest: "Bundle manifest",
  };

  return labels[renderer] || formatRendererLabel(renderer);
}

export function displayArtifactClassLabel(kind: string): string {
  const labels: Record<string, string> = {
    document: "Document artifact",
    visual: "Visual artifact",
    interactive_single_file: "Interactive artifact",
    downloadable_file: "Downloadable artifact",
    workspace_project: "Workspace artifact",
    compound_bundle: "Bundle artifact",
    code_patch: "Code patch artifact",
    report_bundle: "Report bundle",
  };

  return labels[kind] || `${formatStatusLabel(kind)} artifact`;
}

export function formatRuntimeProvenance(
  provenance:
    | NonNullable<ChatArtifactManifest["verification"]["productionProvenance"]>
    | null
    | undefined,
): string {
  if (!provenance) {
    return "Provenance missing";
  }
  const parts = [formatStatusLabel(provenance.kind), provenance.label];
  if (provenance.model) {
    parts.push(provenance.model);
  }
  return parts.filter(Boolean).join(" · ");
}

export function artifactSurfaceTitle(
  artifactClass: string,
  renderer: string,
  file: ChatArtifactManifestFile | null,
  fallbackTitle: string,
): string {
  if (file?.path) {
    return file.path.split("/").pop() || file.path;
  }

  return (
    fallbackTitle ||
    `${displayArtifactClassLabel(artifactClass)} · ${displayRendererLabel(renderer)}`
  );
}

export function mirrorBuildSession(
  buildSession: BuildArtifactSession | null,
): ChatRendererSession | null {
  if (!buildSession) {
    return null;
  }

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
