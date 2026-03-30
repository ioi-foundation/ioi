import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { WorkspaceExplorerPane } from "@ioi/workspace-substrate";

import type { ArtifactContentPayload, StudioArtifactSelectionTarget } from "../../../types";
import { ArtifactRendererHost } from "./ArtifactRendererHost";
import { ArtifactSourceWorkbench } from "./ArtifactSourceWorkbench";
import { StudioArtifactEvidencePanel } from "./StudioArtifactEvidencePanel";
import { StudioArtifactStageHeader } from "./StudioArtifactStageHeader";
import {
  artifactSurfaceTitle,
  displayArtifactClassLabel,
  displayRendererLabel,
  type LogicalArtifactSurfaceProps,
} from "./studioArtifactSurfaceShared";
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

export function StudioArtifactLogicalSurface({
  manifest,
  studioSession,
  rendererSession,
  retrying,
  onRetry,
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
    stageMode === "source"
      ? manifest.renderer
      : renderFile?.mime === "application/pdf"
        ? "pdf_embed"
        : manifest.renderer,
  );
  const stageTitle = artifactSurfaceTitle(
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

        <div className="studio-artifact-sidebar-footer">
          <span className="studio-artifact-badge">
            {manifest.files.length} {manifest.files.length === 1 ? "file" : "files"}
          </span>
          <span className="studio-artifact-badge is-muted">
            {displayArtifactClassLabel(manifest.artifactClass)}
          </span>
        </div>
      </aside>

      <div className="studio-artifact-stage">
        <StudioArtifactStageHeader
          manifest={manifest}
          title={stageTitle}
          activePath={stageMode === "source" ? selectedSourceFile?.path ?? null : renderFile?.path ?? null}
          rendererLabel={rendererLabel}
          retrying={retrying}
          stageMode={stageMode}
          evidenceOpen={evidenceOpen}
          onSelectStageMode={setStageMode}
          onToggleEvidence={() => setEvidenceOpen((current) => !current)}
          onRetry={onRetry}
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
            {stageMode === "source" ? (
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
            <StudioArtifactEvidencePanel
              manifest={manifest}
              studioSession={studioSession}
              pipelineSteps={studioSession.materialization.pipelineSteps ?? []}
              notes={studioSession.materialization.notes}
              evidence={studioSession.verifiedReply.evidence}
              receipts={rendererSession?.receipts}
            />
          ) : null}
        </div>
      </div>
    </section>
  );
}
