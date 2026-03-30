import { useEffect, useMemo, useState, type ReactNode } from "react";
import clsx from "clsx";
import { WorkspaceRail } from "./WorkspaceRail";
import { WorkspaceExplorerPane } from "./WorkspaceExplorerPane";
import { WorkspaceSearchPane } from "./WorkspaceSearchPane";
import { WorkspaceSourceControlPane } from "./WorkspaceSourceControlPane";
import { WorkspaceEditorPane } from "./WorkspaceEditorPane";
import { WorkspaceBottomPanel } from "./WorkspaceBottomPanel";
import { useWorkspaceSession } from "../useWorkspaceSession";
import { useWorkspaceTerminalSession } from "../useWorkspaceTerminalSession";
import type {
  WorkspaceAdapter,
  WorkspaceActivityEntry,
  WorkspaceBottomPanel as WorkspaceBottomPanelType,
  WorkspaceLayoutMode,
  WorkspaceOpenRequest,
  WorkspacePane,
  WorkspaceTerminalController,
} from "../types";

const DEFAULT_VISIBLE_BOTTOM_PANELS: WorkspaceBottomPanelType[] = [
  "terminal",
  "problems",
  "output",
  "ports",
];

export interface WorkspaceHostProps {
  adapter: WorkspaceAdapter;
  root: string;
  layoutMode?: WorkspaceLayoutMode;
  monacoBasePath?: string;
  defaultPane?: WorkspacePane;
  requestedOpen?: WorkspaceOpenRequest | null;
  onActivePathChange?: (path: string | null) => void;
  onAttachSelection?: (payload: { path: string; selection: string }) => void;
  className?: string;
  title?: string;
  showHeader?: boolean;
  headerActions?: ReactNode;
  showBottomPanel?: boolean;
  defaultBottomPanel?: WorkspaceBottomPanelType;
  visibleBottomPanels?: WorkspaceBottomPanelType[];
  onActivityChange?: (activity: WorkspaceActivityEntry[]) => void;
  terminalController?: WorkspaceTerminalController;
  terminalAutoStart?: boolean;
  terminalLaunchRequest?: number;
}

export function WorkspaceHost({
  adapter,
  root,
  layoutMode = "full",
  monacoBasePath = "/monaco/vs",
  defaultPane = "files",
  requestedOpen = null,
  onActivePathChange,
  onAttachSelection,
  className,
  title = "Workspace",
  showHeader = true,
  headerActions,
  showBottomPanel = true,
  defaultBottomPanel = "output",
  visibleBottomPanels = DEFAULT_VISIBLE_BOTTOM_PANELS,
  onActivityChange,
  terminalController: terminalControllerProp,
  terminalAutoStart = false,
  terminalLaunchRequest = 0,
}: WorkspaceHostProps) {
  const [, setTerminalVersion] = useState(0);
  const ownedTerminalController = useWorkspaceTerminalSession({
    adapter,
    root,
    enabled: !terminalControllerProp && terminalAutoStart,
  });
  const terminalController = terminalControllerProp ?? ownedTerminalController;
  const session = useWorkspaceSession({
    adapter,
    root,
    terminalController,
    initialPane: defaultPane,
    initialBottomPanel: defaultBottomPanel,
    externalOpenRequest: requestedOpen,
    onActivePathChange,
    onActivityChange,
  });

  useEffect(() => {
    return terminalController.subscribeState(() => {
      setTerminalVersion((version) => version + 1);
    });
  }, [terminalController]);

  useEffect(() => {
    if (visibleBottomPanels.length === 0) {
      return;
    }
    if (visibleBottomPanels.includes(session.activeBottomPanel)) {
      return;
    }
    session.setActiveBottomPanel(visibleBottomPanels[0]);
  }, [session.activeBottomPanel, session.setActiveBottomPanel, visibleBottomPanels]);

  useEffect(() => {
    if (
      !visibleBottomPanels.includes("terminal") ||
      !session.bottomPanelOpen ||
      session.activeBottomPanel !== "terminal"
    ) {
      return;
    }

    terminalController.start();
  }, [
    session.activeBottomPanel,
    session.bottomPanelOpen,
    terminalController,
    visibleBottomPanels,
  ]);

  useEffect(() => {
    if (terminalLaunchRequest === 0 || !visibleBottomPanels.includes("terminal")) {
      return;
    }

    session.setBottomPanelOpen(true);
    session.setActiveBottomPanel("terminal");
    terminalController.start();
  }, [
    session.setActiveBottomPanel,
    session.setBottomPanelOpen,
    terminalController,
    terminalLaunchRequest,
    visibleBottomPanels,
  ]);

  const pane = useMemo(() => {
    if (session.activePane === "search") {
      return (
        <WorkspaceSearchPane
          searchDraft={session.searchDraft}
          searchLoading={session.searchLoading}
          searchError={session.searchError}
          searchResult={session.searchResult}
          onSearchDraftChange={session.setSearchDraft}
          onRunSearch={session.runSearch}
          onOpenMatch={(match) =>
            void session.openFile({
              path: match.path,
              line: match.line,
              column: match.column,
            })
          }
        />
      );
    }

    if (session.activePane === "source-control") {
      return (
        <WorkspaceSourceControlPane
          state={session.sourceControlState}
          loading={session.sourceControlLoading}
          error={session.sourceControlError}
          onRefresh={() => void session.refreshSourceControl()}
          onOpenDiff={(path, staged) => void session.openDiff(path, staged)}
          onOpenFile={(path) => void session.openFile({ path })}
          onStage={(path) => void session.stagePath(path)}
          onUnstage={(path) => void session.unstagePath(path)}
          onDiscard={(path) => void session.discardPath(path)}
        />
      );
    }

    return (
      <WorkspaceExplorerPane
        tree={session.treeNodes}
        activePath={session.activeFilePath}
        expandedPaths={session.expandedPaths}
        loadingDirectories={session.loadingDirectories}
        git={session.snapshot?.git ?? { isRepo: false, branch: null, dirty: false, lastCommit: null }}
        rootPath={session.snapshot?.rootPath ?? root}
        onToggleDirectory={(node) => void session.toggleDirectory(node)}
        onOpenFile={(path) => void session.openFile({ path })}
        onRefresh={() => void session.loadWorkspace()}
        onCreateFile={() => void session.createFile()}
        onCreateDirectory={() => void session.createDirectory()}
        onRenamePath={(path) => void session.renamePath(path)}
        onDeletePath={(path) => void session.deletePath(path)}
      />
    );
  }, [adapter, root, session]);

  return (
    <section
      className={clsx(
        "workspace-host",
        `workspace-host--${layoutMode}`,
        className,
      )}
      aria-label={title}
    >
      {showHeader ? (
        <header className="workspace-host-header">
          <div className="workspace-host-header-copy">
            <span className="workspace-pane-eyebrow">Autopilot workspace</span>
            <h2>{title}</h2>
            <p>{session.snapshot?.rootPath ?? root}</p>
          </div>
          {headerActions ? <div className="workspace-host-header-actions">{headerActions}</div> : null}
        </header>
      ) : null}

      <div className="workspace-host-body">
        <WorkspaceRail
          activePane={session.activePane}
          onSelectPane={session.setActivePane}
        />

        <div className="workspace-host-sidebar">
          {session.workspaceLoading ? (
            <div className="workspace-pane-message">Loading workspace…</div>
          ) : null}
          {session.workspaceError ? (
            <div className="workspace-pane-message">{session.workspaceError}</div>
          ) : null}
          {!session.workspaceLoading && !session.workspaceError ? pane : null}
        </div>

        <div className="workspace-main">
          <WorkspaceEditorPane
            monacoBasePath={monacoBasePath}
            documents={session.documents}
            activeDocument={session.activeDocument}
            activeDocumentId={session.activeDocumentId}
            revealRequest={session.revealRequest}
            onConsumeRevealRequest={session.consumeRevealRequest}
            onSelectDocument={session.setActiveDocumentId}
            onCloseDocument={session.closeDocument}
            onChangeFileContent={session.updateFileContent}
            onSaveFile={(path) => void session.saveFile(path)}
            onAttachSelection={onAttachSelection}
          />

          {showBottomPanel && visibleBottomPanels.length > 0 ? (
            <WorkspaceBottomPanel
              terminal={terminalController}
              rootPath={session.snapshot?.rootPath ?? root}
              visiblePanels={visibleBottomPanels}
              activePanel={session.activeBottomPanel}
              isOpen={session.bottomPanelOpen}
              outputEntries={session.outputEntries}
              problems={session.problems}
              ports={session.ports}
              onSelectPanel={(panel) => {
                session.setBottomPanelOpen(true);
                session.setActiveBottomPanel(panel);
              }}
              onToggleOpen={() => session.setBottomPanelOpen((isOpen) => !isOpen)}
              onOpenRequest={(request) => void session.openFile(request)}
            />
          ) : null}
        </div>
      </div>
    </section>
  );
}
