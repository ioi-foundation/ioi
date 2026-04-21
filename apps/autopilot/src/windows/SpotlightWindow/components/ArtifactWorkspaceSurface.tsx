import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  WorkspaceExplorerPane,
  useWorkspaceSession,
  useWorkspaceTerminalSession,
  type WorkspaceOpenRequest,
} from "@ioi/workspace-substrate";

import type { ChatArtifactSelectionTarget } from "../../../types";
import { tauriWorkspaceAdapter } from "../../../services/workspaceAdapter";
import { ArtifactRendererHost } from "./ArtifactRendererHost";
import { ArtifactSourceWorkbench } from "./ArtifactSourceWorkbench";
import { ArtifactEvidencePanel } from "./ArtifactEvidencePanel";
import { ArtifactStageHeader } from "./ArtifactStageHeader";
import {
  artifactSurfaceTitle,
  displayArtifactClassLabel,
  displayRendererLabel,
  formatStatusLabel,
  type WorkspaceArtifactSurfaceProps,
} from "./artifactSurfaceShared";
import {
  findArtifactFile,
  hasVerifiedRender,
  resolveInitialStageMode,
} from "./chatArtifactSurfaceModel";

export function ArtifactWorkspaceSurface({
  manifest,
  chatSession,
  rendererSession,
  retrying,
  onRetry,
  onBrowseArtifacts,
  onCollapse,
  onSeedIntent,
}: WorkspaceArtifactSurfaceProps) {
  const [stageMode, setStageMode] = useState(() =>
    resolveInitialStageMode(manifest, rendererSession),
  );
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const requestedOpen = useMemo<WorkspaceOpenRequest | null>(
    () => (rendererSession.entryDocument ? { path: rendererSession.entryDocument } : null),
    [rendererSession.entryDocument],
  );
  const terminalController = useWorkspaceTerminalSession({
    adapter: tauriWorkspaceAdapter,
    root: rendererSession.workspaceRoot,
    enabled: false,
  });
  const session = useWorkspaceSession({
    adapter: tauriWorkspaceAdapter,
    root: rendererSession.workspaceRoot,
    terminalController,
    initialPane: "files",
    initialBottomPanel: "output",
    externalOpenRequest: requestedOpen,
  });

  useEffect(() => {
    setStageMode(resolveInitialStageMode(manifest, rendererSession));
    setEvidenceOpen(false);
  }, [manifest, rendererSession]);

  const activePath = session.activeFilePath ?? rendererSession.entryDocument ?? null;
  const activeFile =
    findArtifactFile(manifest.files, activePath) ??
    findArtifactFile(manifest.files, rendererSession.entryDocument) ??
    manifest.files[0] ??
    null;
  const activeWorkspaceFile =
    session.activeDocument?.kind === "file" ? session.activeDocument : null;
  const headerCopyText =
    activeWorkspaceFile &&
    !activeWorkspaceFile.loading &&
    !activeWorkspaceFile.error &&
    !activeWorkspaceFile.isBinary &&
    !activeWorkspaceFile.isTooLarge
      ? activeWorkspaceFile.content
      : null;
  const hasRender = hasVerifiedRender(manifest, rendererSession);
  const seedSelectionIntent = async (target: ChatArtifactSelectionTarget) => {
    await invoke("chat_attach_artifact_selection", { selection: target });
    onSeedIntent(
      `Edit only this artifact selection from ${target.sourceSurface}${target.path ? ` (${target.path})` : ""}:\n\n${target.snippet}`,
    );
  };
  const stageTitle = artifactSurfaceTitle(
    manifest.artifactClass,
    manifest.renderer,
    stageMode === "source" ? activeFile : null,
    manifest.title,
  );

  const handleOpenWorkspacePath = (path: string) => {
    void session.openFile({ path });
    if (stageMode === "render" && !hasRender) {
      setStageMode("source");
    }
  };

  return (
    <section className="chat-artifact-surface" aria-label="Chat artifact surface">
      <aside className="chat-artifact-sidebar chat-artifact-sidebar--explorer">
        <WorkspaceExplorerPane
          tree={session.treeNodes}
          activePath={session.activeFilePath}
          expandedPaths={session.expandedPaths}
          loadingDirectories={session.loadingDirectories}
          git={session.snapshot?.git ?? { isRepo: false, branch: null, dirty: false, lastCommit: null }}
          rootPath={session.snapshot?.rootPath ?? rendererSession.workspaceRoot}
          eyebrow="Workspace"
          title="Explorer"
          readOnly={true}
          showGitSummary={false}
          showRefreshButton={true}
          onToggleDirectory={(node) => void session.toggleDirectory(node)}
          onOpenFile={handleOpenWorkspacePath}
          onRefresh={() => void session.loadWorkspace()}
          onCreateFile={() => undefined}
          onCreateDirectory={() => undefined}
          onRenamePath={(_path: string) => undefined}
          onDeletePath={(_path: string) => undefined}
        />

        <div className="chat-artifact-sidebar-footer">
          <span className="chat-artifact-badge">
            {displayArtifactClassLabel(manifest.artifactClass)}
          </span>
          <span className="chat-artifact-badge is-muted">
            {formatStatusLabel(manifest.verification.status)}
          </span>
        </div>
      </aside>

      <div className="chat-artifact-stage">
        <ArtifactStageHeader
          manifest={manifest}
          title={stageTitle}
          activePath={activePath}
          copyText={headerCopyText}
          copyPath={activePath}
          rendererLabel={displayRendererLabel(manifest.renderer)}
          swarmExecution={chatSession.materialization.swarmExecution}
          retrying={retrying}
          stageMode={stageMode}
          evidenceOpen={evidenceOpen}
          onSelectStageMode={setStageMode}
          onToggleEvidence={() => setEvidenceOpen((current) => !current)}
          onRetry={onRetry}
          onBrowseArtifacts={onBrowseArtifacts}
          onCollapse={onCollapse}
        />

        {session.workspaceError ? (
          <div className="chat-artifact-banner is-error">{session.workspaceError}</div>
        ) : null}

        {!hasRender && stageMode === "render" ? (
          <div className="chat-artifact-banner">
            Render becomes primary after preview verification. Source remains the default until a
            verified preview exists.
          </div>
        ) : null}

        <div className={`chat-artifact-stage-layout ${evidenceOpen ? "is-evidence-open" : ""}`}>
          <div className="chat-artifact-stage-main">
            {stageMode === "source" ? (
              <section className="chat-artifact-source-workbench workspace-host workspace-host--embedded">
                <ArtifactSourceWorkbench
                  artifactId={manifest.artifactId}
                  files={manifest.files}
                  selectedFile={activeFile}
                  payload={
                    activeWorkspaceFile &&
                    !activeWorkspaceFile.loading &&
                    !activeWorkspaceFile.error &&
                    !activeWorkspaceFile.isBinary &&
                    !activeWorkspaceFile.isTooLarge
                      ? {
                          artifact_id:
                            activeFile?.artifactId ?? manifest.artifactId,
                          encoding: "utf-8",
                          content: activeWorkspaceFile.content,
                        }
                      : null
                  }
                  sourceTextOverride={
                    activeWorkspaceFile &&
                    !activeWorkspaceFile.loading &&
                    !activeWorkspaceFile.error &&
                    !activeWorkspaceFile.isBinary &&
                    !activeWorkspaceFile.isTooLarge
                      ? activeWorkspaceFile.content
                      : null
                  }
                  loading={Boolean(activeWorkspaceFile?.loading)}
                  error={activeWorkspaceFile?.error ?? session.workspaceError}
                  binaryOverride={Boolean(activeWorkspaceFile?.isBinary)}
                  tooLargeOverride={Boolean(activeWorkspaceFile?.isTooLarge)}
                  onSelectPath={handleOpenWorkspacePath}
                  onAttachSelection={({ path, selection }) =>
                    void seedSelectionIntent({
                      sourceSurface: "source",
                      path,
                      label: "Selected workspace excerpt",
                      snippet: selection,
                    })
                  }
                  showExplorer={false}
                />
              </section>
            ) : (
              <ArtifactRendererHost
                renderer={manifest.renderer}
                title={manifest.title}
                file={activeFile}
                files={manifest.files}
                rendererSession={rendererSession}
                requestedOpen={requestedOpen}
                onAttachSelection={({ path, selection }) =>
                  void seedSelectionIntent({
                    sourceSurface: "render",
                    path,
                    label: "Selected preview excerpt",
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
              receipts={rendererSession.receipts}
              workspaceActivity={session.activity}
            />
          ) : null}
        </div>
      </div>
    </section>
  );
}
