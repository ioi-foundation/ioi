import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { WorkspaceExplorerPane } from "@ioi/workspace-substrate";

import type { ArtifactContentPayload, StudioArtifactSelectionTarget } from "../../../types";
import { ArtifactRendererHost } from "./ArtifactRendererHost";
import { ArtifactSourceWorkbench } from "./ArtifactSourceWorkbench";
import { ArtifactEvidencePanel } from "./ArtifactEvidencePanel";
import { ArtifactStageHeader } from "./ArtifactStageHeader";
import { formatStudioExecutionPreviewPhase } from "./studioExecutionPreview";
import {
  artifactSurfaceTitle,
  displayArtifactClassLabel,
  displayRendererLabel,
  formatStatusLabel,
  type LogicalArtifactSurfaceProps,
} from "./artifactSurfaceShared";
import {
  buildArtifactTree,
  expandArtifactAncestors,
  findArtifactFile,
  hasVerifiedRender,
  resolveInitialStageMode,
  resolveRenderFile,
  resolveSourceFilePath,
  shouldSwitchToSourceForSelection,
} from "./studioArtifactSurfaceModel";
import { deriveStudioExecutionChrome } from "./studioExecutionChrome";

function isTextMime(mime: string | null | undefined): boolean {
  const normalized = String(mime || "").trim().toLowerCase();
  if (!normalized) {
    return true;
  }

  return (
    normalized.startsWith("text/") ||
    normalized.includes("json") ||
    normalized.includes("javascript") ||
    normalized.includes("typescript") ||
    normalized.includes("xml") ||
    normalized.includes("yaml") ||
    normalized.includes("svg") ||
    normalized.includes("html") ||
    normalized.includes("markdown")
  );
}

function decodeArtifactPayloadText(
  payload: ArtifactContentPayload | null,
): string | null {
  if (!payload) {
    return null;
  }

  if (payload.encoding === "base64") {
    try {
      return window.atob(payload.content);
    } catch {
      return null;
    }
  }

  return payload.content;
}

function previewMode(
  preview:
    | {
        kind?: string | null;
      }
    | null
    | undefined,
) {
  return preview?.kind === "change_preview" ? "code" : "stream";
}

function formatPreviewStats(content: string) {
  const lineCount = content.split(/\r?\n/).length;
  const charCount = content.length;
  return `${lineCount.toLocaleString()} lines · ${charCount.toLocaleString()} chars`;
}

export function ArtifactLogicalSurface({
  manifest,
  chatSession,
  rendererSession,
  retrying,
  onRetry,
  onBrowseArtifacts,
  onCollapse,
  onSeedIntent,
}: LogicalArtifactSurfaceProps) {
  const [stageMode, setStageMode] = useState(() =>
    resolveInitialStageMode(manifest, rendererSession),
  );
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const [sourceFilePath, setSourceFilePath] = useState<string | null>(() =>
    resolveSourceFilePath(manifest),
  );
  const [expandedPaths, setExpandedPaths] = useState<Record<string, boolean>>({});
  const [artifactPayload, setArtifactPayload] = useState<ArtifactContentPayload | null>(null);
  const [artifactError, setArtifactError] = useState<string | null>(null);
  const [artifactLoading, setArtifactLoading] = useState(false);
  const executionEnvelope = chatSession.materialization.executionEnvelope ?? null;
  const executionChrome = deriveStudioExecutionChrome({
    executionEnvelope,
    swarmExecution: chatSession.materialization.swarmExecution,
    swarmPlan: chatSession.materialization.swarmPlan,
    workerReceipts: chatSession.materialization.swarmWorkerReceipts,
    changeReceipts: chatSession.materialization.swarmChangeReceipts,
  });
  const livePreview = executionChrome.livePreview;
  const codePreview = executionChrome.codePreview;
  const renderExecutionPreviewAriaLabel = (
    preview: NonNullable<typeof livePreview>,
  ) =>
    `${preview.label}. ${formatStudioExecutionPreviewPhase(preview)}.`;
  const isNonArtifactRoute = chatSession.outcomeRequest.outcomeKind !== "artifact";
  const routeLabel = formatStatusLabel(chatSession.outcomeRequest.outcomeKind);
  const routeHints = (chatSession.outcomeRequest.routingHints ?? []).slice(0, 4);
  const showRouteSummary = isNonArtifactRoute && manifest.files.length === 0;
  const showZeroFileArtifactStage = !showRouteSummary && manifest.files.length === 0;

  useEffect(() => {
    setStageMode(resolveInitialStageMode(manifest, rendererSession));
    setEvidenceOpen(false);
    setSourceFilePath(resolveSourceFilePath(manifest));
  }, [manifest, rendererSession]);

  useEffect(() => {
    if (!sourceFilePath) {
      return;
    }
    setExpandedPaths((current) => expandArtifactAncestors(current, sourceFilePath));
  }, [sourceFilePath]);

  const selectedSourceFile = useMemo(
    () => findArtifactFile(manifest.files, sourceFilePath) ?? resolveRenderFile(manifest),
    [manifest, sourceFilePath],
  );
  const renderFile = useMemo(
    () => resolveRenderFile(manifest, sourceFilePath),
    [manifest, sourceFilePath],
  );
  const activeStageFile = stageMode === "source" ? selectedSourceFile : renderFile;
  const headerCopyText = useMemo(() => {
    if (!activeStageFile || !isTextMime(activeStageFile.mime)) {
      return null;
    }
    return decodeArtifactPayloadText(artifactPayload);
  }, [activeStageFile, artifactPayload]);

  useEffect(() => {
    let cancelled = false;
    const artifactId = activeStageFile?.artifactId;
    if (!artifactId) {
      setArtifactLoading(false);
      setArtifactPayload(null);
      setArtifactError(null);
      return;
    }

    const load = async () => {
      setArtifactLoading(true);
      setArtifactPayload(null);
      setArtifactError(null);
      try {
        const payload = await invoke<ArtifactContentPayload | null>("get_artifact_content", {
          artifactId,
          artifact_id: artifactId,
        });
        if (!cancelled) {
          setArtifactPayload(payload);
          setArtifactLoading(false);
        }
      } catch (error) {
        if (!cancelled) {
          setArtifactPayload(null);
          setArtifactError(String(error));
          setArtifactLoading(false);
        }
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [activeStageFile?.artifactId]);

  const rendererLabel = displayRendererLabel(
    showRouteSummary
      ? chatSession.outcomeRequest.outcomeKind
      : stageMode === "source"
        ? manifest.renderer
        : renderFile?.mime === "application/pdf"
          ? "pdf_embed"
          : manifest.renderer,
  );
  const stageTitle = showRouteSummary
    ? chatSession.verifiedReply.title
    : artifactSurfaceTitle(
        manifest.artifactClass,
        manifest.renderer,
        stageMode === "source" ? selectedSourceFile : renderFile,
        manifest.title,
      );
  const tree = useMemo(() => buildArtifactTree(manifest.files), [manifest.files]);
  const hasRender = hasVerifiedRender(manifest, rendererSession);

  const seedSelectionIntent = async (target: StudioArtifactSelectionTarget) => {
    await invoke("studio_attach_artifact_selection", { selection: target });
    onSeedIntent(
      `Edit only this artifact selection from ${target.sourceSurface}${target.path ? ` (${target.path})` : ""}:\n\n${target.snippet}`,
    );
  };

  const handleSelectPath = (path: string) => {
    const nextFile = findArtifactFile(manifest.files, path);
    setExpandedPaths((current) => expandArtifactAncestors(current, path));
    setSourceFilePath(path);
    if (stageMode === "render" && shouldSwitchToSourceForSelection(manifest, nextFile)) {
      setStageMode("source");
    }
  };

  return (
    <section className="studio-artifact-surface" aria-label="Studio artifact surface">
      <aside className="studio-artifact-sidebar studio-artifact-sidebar--explorer">
        {showRouteSummary ? (
          <div className="studio-artifact-renderer-empty">
            <strong>{routeLabel} stays primary</strong>
            <p>{chatSession.verifiedReply.summary}</p>
          </div>
        ) : showZeroFileArtifactStage ? (
          <div className="studio-artifact-renderer-empty">
                <strong>
              {manifest.verification.lifecycleState === "blocked"
                ? "Artifact build blocked before the first file landed."
                : manifest.verification.lifecycleState === "failed"
                  ? "Artifact build failed before the first file landed."
                  : "Artifact files are still materializing."}
            </strong>
            <p>{manifest.verification.summary || chatSession.verifiedReply.summary}</p>
          </div>
        ) : (
          <WorkspaceExplorerPane
            tree={tree}
            activePath={sourceFilePath}
            expandedPaths={expandedPaths}
            loadingDirectories={{}}
            git={{ isRepo: false, branch: null, dirty: false, lastCommit: null }}
            rootPath={`artifact://${manifest.artifactId}`}
            eyebrow="Artifact"
            title="Explorer"
            readOnly={true}
            showGitSummary={false}
            showRefreshButton={false}
            onToggleDirectory={(node) =>
              setExpandedPaths((current) => ({
                ...current,
                [node.path]: !current[node.path],
              }))
            }
            onOpenFile={handleSelectPath}
            onRefresh={() => undefined}
            onCreateFile={() => undefined}
            onCreateDirectory={() => undefined}
            onRenamePath={(_path: string) => undefined}
            onDeletePath={(_path: string) => undefined}
          />
        )}

        <div className="studio-artifact-sidebar-footer">
          <span className="studio-artifact-badge">
            {showRouteSummary
              ? routeLabel
              : `${manifest.files.length} ${manifest.files.length === 1 ? "file" : "files"}`}
          </span>
          <span className="studio-artifact-badge is-muted">
            {showRouteSummary
              ? formatStatusLabel(chatSession.outcomeRequest.executionStrategy)
              : displayArtifactClassLabel(manifest.artifactClass)}
          </span>
          {showRouteSummary
            ? routeHints.map((hint) => (
                <span key={hint} className="studio-artifact-badge is-muted">
                  {hint}
                </span>
              ))
            : null}
        </div>
      </aside>

      <div className="studio-artifact-stage">
        <ArtifactStageHeader
          manifest={manifest}
          title={stageTitle}
          stageKicker={showRouteSummary ? `${routeLabel} route` : undefined}
          activePath={stageMode === "source" ? selectedSourceFile?.path ?? null : renderFile?.path ?? null}
          copyText={headerCopyText}
          copyPath={activeStageFile?.path ?? null}
          rendererLabel={rendererLabel}
          swarmExecution={chatSession.materialization.swarmExecution}
          retrying={retrying}
          stageMode={stageMode}
          evidenceOpen={evidenceOpen}
          showStageModes={!showRouteSummary && !showZeroFileArtifactStage}
          onSelectStageMode={setStageMode}
          onToggleEvidence={() => setEvidenceOpen((current) => !current)}
          onRetry={onRetry}
          onBrowseArtifacts={onBrowseArtifacts}
          onCollapse={onCollapse}
        />

        {artifactError ? <div className="studio-artifact-banner is-error">{artifactError}</div> : null}

        {!hasRender && stageMode === "render" ? (
          <div className="studio-artifact-banner">
            Render exists only as an unverified outcome right now. Studio keeps Source as the
            default until presentation quality clears verification.
          </div>
        ) : null}

        <div className={`studio-artifact-stage-layout ${evidenceOpen ? "is-evidence-open" : ""}`}>
          <div className="studio-artifact-stage-main">
            {showRouteSummary ? (
              <section className="studio-artifact-renderer-shell">
                <div className="studio-artifact-renderer-empty">
                  <strong>{routeLabel} route verified</strong>
                  <p>{chatSession.verifiedReply.summary}</p>
                  {routeHints.length ? (
                    <p>{routeHints.join(" · ")}</p>
                  ) : null}
                  {chatSession.materialization.swarmExecution ? (
                    <p>
                      {chatSession.materialization.swarmExecution.completedWorkItems}/
                      {chatSession.materialization.swarmExecution.totalWorkItems} work items
                      completed · {formatStatusLabel(chatSession.materialization.swarmExecution.verificationStatus)}
                    </p>
                  ) : null}
                </div>
              </section>
            ) : showZeroFileArtifactStage ? (
              <section className="studio-artifact-renderer-shell">
                <div className="studio-artifact-renderer-empty">
                  <strong>
                    {manifest.verification.lifecycleState === "blocked"
                      ? "Artifact build blocked before the first renderable file landed."
                      : manifest.verification.lifecycleState === "failed"
                        ? "Artifact build failed before the first renderable file landed."
                        : "Building the first renderable artifact files…"}
                  </strong>
                <p>{manifest.verification.summary || chatSession.verifiedReply.summary}</p>
                {chatSession.materialization.swarmExecution ? (
                  <p>
                    {chatSession.materialization.swarmExecution.completedWorkItems}/
                    {chatSession.materialization.swarmExecution.totalWorkItems} work items
                    completed · {formatStatusLabel(
                      chatSession.materialization.swarmExecution.currentStage,
                    )}
                  </p>
                ) : null}
                {executionChrome.processes.length ? (
                  <div
                    className="spot-studio-status-process-list"
                    aria-label="Thinking processes"
                  >
                    {executionChrome.processes.map((process) => (
                      <div
                        key={process.id}
                        className={`spot-studio-status-process ${
                          process.isActive ? "is-active" : ""
                        }`}
                        aria-label={`${process.label}. ${process.status}. ${process.summary}`}
                      >
                        <div className="spot-studio-status-process-row">
                          <strong>{process.label}</strong>
                          <span>{process.status}</span>
                        </div>
                        <p>{process.summary}</p>
                      </div>
                    ))}
                  </div>
                ) : null}
                {livePreview?.content ? (
                  <div
                    className={`spot-studio-status-preview ${
                      previewMode(livePreview) === "code"
                        ? "is-code-preview"
                        : "is-stream-preview"
                    }`}
                    aria-live="polite"
                    aria-label={renderExecutionPreviewAriaLabel(livePreview)}
                  >
                    <div className="spot-studio-status-preview-head">
                      <span>{livePreview.label}</span>
                      <span>
                        {formatStudioExecutionPreviewPhase(livePreview)}
                      </span>
                    </div>
                    <div className="spot-studio-status-preview-meta">
                      <span>{formatPreviewStats(livePreview.content)}</span>
                      {previewMode(livePreview) === "code" ? (
                        <span>Scroll to inspect the full artifact.</span>
                      ) : null}
                    </div>
                    <pre
                      className={`studio-artifact-pending-preview ${
                        previewMode(livePreview) === "code"
                          ? "is-code-preview"
                          : "is-stream-preview"
                      }`}
                      tabIndex={0}
                    >
                      <code>{livePreview.content}</code>
                    </pre>
                  </div>
                ) : null}
                {codePreview?.content && codePreview.content !== livePreview?.content ? (
                  <div
                    className={`spot-studio-status-preview ${
                      previewMode(codePreview) === "code"
                        ? "is-code-preview"
                        : "is-stream-preview"
                    }`}
                    aria-live="polite"
                    aria-label={renderExecutionPreviewAriaLabel(codePreview)}
                  >
                    <div className="spot-studio-status-preview-head">
                      <span>{codePreview.label}</span>
                      <span>
                        {formatStudioExecutionPreviewPhase(codePreview)}
                      </span>
                    </div>
                    <div className="spot-studio-status-preview-meta">
                      <span>{formatPreviewStats(codePreview.content)}</span>
                      {previewMode(codePreview) === "code" ? (
                        <span>Scroll to inspect the full artifact.</span>
                      ) : null}
                    </div>
                    <pre
                      className={`studio-artifact-pending-preview ${
                        previewMode(codePreview) === "code"
                          ? "is-code-preview"
                          : "is-stream-preview"
                      }`}
                      tabIndex={0}
                    >
                      <code>{codePreview.content}</code>
                    </pre>
                  </div>
                ) : null}
              </div>
            </section>
            ) : stageMode === "source" ? (
              <ArtifactSourceWorkbench
                artifactId={manifest.artifactId}
                files={manifest.files}
                selectedFile={selectedSourceFile}
                payload={artifactPayload}
                loading={artifactLoading}
                error={artifactError}
                onSelectPath={handleSelectPath}
                onAttachSelection={({ path, selection }) =>
                  void seedSelectionIntent({
                    sourceSurface: "source",
                    path,
                    label: "Selected source excerpt",
                    snippet: selection,
                  })
                }
                showExplorer={false}
              />
            ) : artifactLoading && !artifactPayload ? (
              <div className="studio-artifact-renderer-empty">
                <strong>Loading artifact render…</strong>
              </div>
            ) : (
              <ArtifactRendererHost
                renderer={manifest.renderer}
                title={manifest.title}
                file={renderFile}
                files={manifest.files}
                payload={artifactPayload}
                rendererSession={rendererSession}
                onAttachSelection={({ path, selection }) =>
                  void seedSelectionIntent({
                    sourceSurface: "render",
                    path,
                    label: "Selected render excerpt",
                    snippet: selection,
                  })
                }
              />
            )}
          </div>

          {evidenceOpen ? (
            <ArtifactEvidencePanel
              manifest={manifest}
              chatSession={chatSession}
              pipelineSteps={chatSession.materialization.pipelineSteps ?? []}
              notes={chatSession.materialization.notes}
              evidence={chatSession.verifiedReply.evidence}
              receipts={rendererSession?.receipts}
            />
          ) : null}
        </div>
      </div>
    </section>
  );
}
