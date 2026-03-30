import type { WorkspaceActivityEntry } from "@ioi/workspace-substrate";

import type { AgentTask } from "../../../store/agentStore";
import type {
  BuildArtifactSession,
  StudioArtifactManifest,
  StudioArtifactManifestFile,
  StudioArtifactPipelineStep,
  StudioRendererSession,
} from "../../../types";
import type { StudioArtifactStageMode } from "./studioArtifactSurfaceModel";

export interface StudioArtifactSurfaceProps {
  task: AgentTask | null;
  onSeedIntent: (intent: string) => void;
  onCollapse?: () => void;
}

export interface SurfaceStageHeaderProps {
  manifest: StudioArtifactManifest;
  title: string;
  activePath: string | null;
  rendererLabel: string;
  retrying: boolean;
  stageMode: StudioArtifactStageMode;
  evidenceOpen: boolean;
  onSelectStageMode: (mode: StudioArtifactStageMode) => void;
  onToggleEvidence: () => void;
  onRetry: (() => void) | null;
  onCollapse?: (() => void) | null;
}

export interface ArtifactEvidencePanelProps {
  manifest: StudioArtifactManifest;
  studioSession: NonNullable<AgentTask["studio_session"]>;
  pipelineSteps: StudioArtifactPipelineStep[];
  notes: string[];
  evidence: string[];
  receipts?: BuildArtifactSession["receipts"];
  workspaceActivity?: WorkspaceActivityEntry[];
}

export interface StudioArtifactRevisionComparison {
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
  manifest: StudioArtifactManifest;
  studioSession: NonNullable<AgentTask["studio_session"]>;
  rendererSession: StudioRendererSession | null;
  retrying: boolean;
  onRetry: (() => void) | null;
  onCollapse?: (() => void) | null;
  onSeedIntent: (intent: string) => void;
}

export interface WorkspaceArtifactSurfaceProps {
  manifest: StudioArtifactManifest;
  studioSession: NonNullable<AgentTask["studio_session"]>;
  rendererSession: StudioRendererSession;
  retrying: boolean;
  onRetry: (() => void) | null;
  onCollapse?: (() => void) | null;
  onSeedIntent: (intent: string) => void;
}

export function formatStatusLabel(status: string | null | undefined): string {
  if (!status) {
    return "Pending";
  }
  return status
    .split(/[-_]/)
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
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
    | NonNullable<StudioArtifactManifest["verification"]["productionProvenance"]>
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
  file: StudioArtifactManifestFile | null,
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
): StudioRendererSession | null {
  if (!buildSession) {
    return null;
  }

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
