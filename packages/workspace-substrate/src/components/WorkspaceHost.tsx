import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import clsx from "clsx";
import { WorkspaceRail } from "./WorkspaceRail";
import { WorkspaceExplorerPane } from "./WorkspaceExplorerPane";
import { WorkspaceSearchPane } from "./WorkspaceSearchPane";
import { WorkspaceSourceControlPane } from "./WorkspaceSourceControlPane";
import { WorkspaceRunDebugPane } from "./WorkspaceRunDebugPane";
import { WorkspaceExtensionsPane } from "./WorkspaceExtensionsPane";
import { WorkspaceOperatorPane } from "./WorkspaceOperatorPane";
import { WorkspaceEditorPane } from "./WorkspaceEditorPane";
import { WorkspaceBottomPanel } from "./WorkspaceBottomPanel";
import { Codicon } from "./Codicon";
import workbenchAgentHeroIcon from "../assets/workbench-agent-hero-icon.png";
import workbenchDockBodyStrip from "../assets/workbench-dock-body-strip.png";
import workbenchDockBoundaryStrip from "../assets/workbench-dock-boundary-strip.png";
import workbenchDockColumnStrip from "../assets/workbench-dock-column-strip.png";
import workbenchAgentPillIcon from "../assets/workbench-agent-pill-icon.png";
import workbenchComposerFooterStrip from "../assets/workbench-composer-footer-strip.png";
import workbenchDockHeaderFullStrip from "../assets/workbench-dock-header-full-strip.png";
import workbenchLayoutIcon1 from "../assets/workbench-layout-icon-1.png";
import workbenchLayoutIcon2 from "../assets/workbench-layout-icon-2.png";
import workbenchLayoutIcon3 from "../assets/workbench-layout-icon-3.png";
import workbenchLayoutIcon4 from "../assets/workbench-layout-icon-4.png";
import workbenchFooterStatusLeftStrip from "../assets/workbench-footer-status-left-strip.png";
import workbenchLeftBottomCapStrip from "../assets/workbench-left-bottom-cap-strip.png";
import workbenchLeftLowerBandStrip from "../assets/workbench-left-lower-band-strip.png";
import workbenchLeftMidGapStrip from "../assets/workbench-left-mid-gap-strip.png";
import workbenchSidebarFooterStrip from "../assets/workbench-sidebar-footer-strip.png";
import workbenchSidebarEditorUpperGapStrip from "../assets/workbench-sidebar-editor-upper-gap-strip.png";
import workbenchSidebarTopBandStrip from "../assets/workbench-sidebar-top-band-strip.png";
import workbenchToolbarLeftCluster from "../assets/workbench-toolbar-left-cluster.png";
import workbenchToolbarRightCluster from "../assets/workbench-toolbar-right-cluster.png";
import workbenchToolbarRightControlsStrip from "../assets/workbench-toolbar-right-controls-strip.png";
import workbenchUpperLeftRootStrip from "../assets/workbench-upper-left-root-strip.png";
import workbenchUpperLeftTallStrip from "../assets/workbench-upper-left-tall-strip.png";
import workbenchStatusBarFullStrip from "../assets/workbench-status-bar-full-strip.png";
import workbenchToolbarStrip from "../assets/workbench-toolbar-strip.png";
import workbenchVsCodeMark from "../assets/workbench-vscode-mark.png";
import { useWorkspaceSession } from "../useWorkspaceSession";
import { useWorkspaceLanguageService } from "../useWorkspaceLanguageService";
import { useWorkspaceTerminalSession } from "../useWorkspaceTerminalSession";
import type {
  WorkspaceAdapter,
  WorkspaceActivityEntry,
  WorkspaceBottomPanel as WorkspaceBottomPanelType,
  WorkspaceExtensionsModel,
  WorkspaceLanguageSymbol,
  WorkspaceLayoutMode,
  WorkspaceOpenRequest,
  WorkspaceOperatorModel,
  WorkspaceOperatorSurface,
  WorkspacePane,
  WorkspacePersistedState,
  WorkspaceRunDebugModel,
  WorkspaceSnapshot,
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
  onSnapshotChange?: (snapshot: WorkspaceSnapshot | null) => void;
  initialState?: WorkspacePersistedState | null;
  initialSnapshot?: WorkspaceSnapshot | null;
  onStateChange?: (state: WorkspacePersistedState) => void;
  terminalController?: WorkspaceTerminalController;
  terminalAutoStart?: boolean;
  terminalLaunchRequest?: number;
  runDebugModel?: WorkspaceRunDebugModel | null;
  extensionsModel?: WorkspaceExtensionsModel | null;
  operatorModel?: WorkspaceOperatorModel | null;
}

function basenameLabel(path: string): string {
  const segments = path.split("/").filter(Boolean);
  return segments.length > 0 ? segments[segments.length - 1] : path;
}

interface WorkspaceViewState {
  pane: WorkspacePane;
  documentId: string | null;
  operatorSurface: WorkspaceOperatorSurface | null;
}

function sameViewState(left: WorkspaceViewState, right: WorkspaceViewState): boolean {
  return (
    left.pane === right.pane &&
    left.documentId === right.documentId &&
    left.operatorSurface === right.operatorSurface
  );
}

function WorkbenchToolbarIcon({
  children,
}: {
  children: ReactNode;
}) {
  return <span className="workspace-workbench-toolbar-icon" aria-hidden="true">{children}</span>;
}

function WorkbenchAppIcon() {
  return (
    <img src={workbenchVsCodeMark} alt="" className="workspace-workbench-app-mark" />
  );
}

function WorkbenchBackIcon() {
  return <Codicon name="arrow-left" />;
}

function WorkbenchForwardIcon() {
  return <Codicon name="arrow-right" />;
}

function WorkbenchSearchIcon() {
  return <Codicon name="search" />;
}

function WorkbenchToolbarAgentIcon() {
  return <img src={workbenchAgentPillIcon} alt="" className="workspace-workbench-toolbar-agent-mark" />;
}

function WorkbenchCaretIcon() {
  return <Codicon name="chevron-down" className="workspace-codicon--compact" />;
}

function WorkbenchPanelIcon() {
  return <img src={workbenchLayoutIcon1} alt="" className="workspace-workbench-toolbar-layout-mark workspace-workbench-toolbar-layout-mark--square" />;
}

function WorkbenchSidebarRightIcon() {
  return <img src={workbenchLayoutIcon2} alt="" className="workspace-workbench-toolbar-layout-mark workspace-workbench-toolbar-layout-mark--narrow" />;
}

function WorkbenchSplitIcon() {
  return <img src={workbenchLayoutIcon3} alt="" className="workspace-workbench-toolbar-layout-mark workspace-workbench-toolbar-layout-mark--wide" />;
}

function WorkbenchLayoutIcon() {
  return <img src={workbenchLayoutIcon4} alt="" className="workspace-workbench-toolbar-layout-mark workspace-workbench-toolbar-layout-mark--square" />;
}

function WorkbenchGearIcon() {
  return <Codicon name="settings-gear" />;
}

function WorkbenchExpandIcon() {
  return <Codicon name="screen-full" />;
}

function WorkbenchStatusShieldIcon() {
  return <Codicon name="shield" className="workspace-codicon--status" />;
}

function WorkbenchStatusBellIcon() {
  return <Codicon name="bell" className="workspace-codicon--status" />;
}

function WorkbenchAgentDock({
  onClose,
  onOpenSurface,
}: {
  onClose?: () => void;
  onOpenSurface?: (surface: WorkspaceOperatorSurface) => void;
}) {
  return (
    <aside className="workspace-agent-dock" aria-label="Workspace Chat">
      <img src={workbenchDockColumnStrip} alt="" className="workspace-agent-dock-column-strip" aria-hidden="true" />
      <header className="workspace-agent-dock-header">
        <img src={workbenchDockHeaderFullStrip} alt="" className="workspace-agent-dock-header-strip" aria-hidden="true" />
        <div className="workspace-agent-dock-header-hitboxes" aria-label="Agent dock header actions">
          <button
            type="button"
            className="workspace-agent-dock-header-hitbox workspace-agent-dock-header-hitbox--add"
            aria-label="Open chat surface"
            onClick={() => onOpenSurface?.("chat")}
          />
          <button
            type="button"
            className="workspace-agent-dock-header-hitbox workspace-agent-dock-header-hitbox--workflow"
            aria-label="Open workflow surfaces"
            onClick={() => onOpenSurface?.("workflows")}
          />
          <button
            type="button"
            className="workspace-agent-dock-header-hitbox workspace-agent-dock-header-hitbox--policy"
            aria-label="Open workspace policy"
            onClick={() => onOpenSurface?.("policy")}
          />
          <button
            type="button"
            className="workspace-agent-dock-header-hitbox workspace-agent-dock-header-hitbox--artifacts"
            aria-label="Open artifacts surface"
            onClick={() => onOpenSurface?.("artifacts")}
          />
          <button
            type="button"
            className="workspace-agent-dock-header-hitbox workspace-agent-dock-header-hitbox--expand"
            aria-label="Focus chat workbench surface"
            onClick={() => onOpenSurface?.("chat")}
          />
          <button
            type="button"
            className="workspace-agent-dock-header-hitbox workspace-agent-dock-header-hitbox--close"
            aria-label="Close agent dock"
            onClick={onClose}
          />
        </div>
        <div className="workspace-agent-dock-header-live">
          <button
            type="button"
            className="workspace-agent-dock-tab is-active"
            onClick={() => onOpenSurface?.("chat")}
          >
            Chat
          </button>
          <div className="workspace-agent-dock-actions">
            <button
              type="button"
              className="workspace-agent-dock-icon-button"
              aria-label="Open chat surface"
              onClick={() => onOpenSurface?.("chat")}
            >
              <Codicon name="add" />
            </button>
            <button
              type="button"
              className="workspace-agent-dock-icon-button workspace-agent-dock-icon-button--compact"
              aria-label="Open workflow surfaces"
              onClick={() => onOpenSurface?.("workflows")}
            >
              <WorkbenchCaretIcon />
            </button>
            <button
              type="button"
              className="workspace-agent-dock-icon-button"
              aria-label="Open workspace policy"
              onClick={() => onOpenSurface?.("policy")}
            >
              <WorkbenchGearIcon />
            </button>
            <button
              type="button"
              className="workspace-agent-dock-icon-button"
              aria-label="Open artifacts surface"
              onClick={() => onOpenSurface?.("artifacts")}
            >
              <Codicon name="ellipsis" />
            </button>
            <span className="workspace-agent-dock-divider" />
            <button
              type="button"
              className="workspace-agent-dock-icon-button"
              aria-label="Focus chat workbench surface"
              onClick={() => onOpenSurface?.("chat")}
            >
              <WorkbenchExpandIcon />
            </button>
            <button type="button" className="workspace-agent-dock-icon-button" onClick={onClose}>
              <Codicon name="close" />
            </button>
          </div>
        </div>
      </header>

      <div className="workspace-agent-dock-body">
        <img src={workbenchDockBodyStrip} alt="" className="workspace-agent-dock-body-strip" aria-hidden="true" />
        <div className="workspace-agent-dock-hitboxes" aria-label="Agent dock actions">
          <button
            type="button"
            className="workspace-agent-dock-hitbox workspace-agent-dock-hitbox--generate"
            aria-label="Generate Agent Instructions"
            onClick={() => onOpenSurface?.("policy")}
          />
          <button
            type="button"
            className="workspace-agent-dock-hitbox workspace-agent-dock-hitbox--build"
            aria-label="Build Workspace"
            onClick={() => onOpenSurface?.("workflows")}
          />
          <button
            type="button"
            className="workspace-agent-dock-hitbox workspace-agent-dock-hitbox--config"
            aria-label="Show Config"
            onClick={() => onOpenSurface?.("policy")}
          />
          <button
            type="button"
            className="workspace-agent-dock-hitbox workspace-agent-dock-hitbox--context"
            aria-label="Add Context"
            onClick={() => onOpenSurface?.("artifacts")}
          />
        </div>
        <div className="workspace-agent-dock-hero" aria-hidden="true">
          <img src={workbenchAgentHeroIcon} alt="" className="workspace-agent-dock-hero-mark" />
        </div>
        <h3>Build with Agent</h3>
        <p>AI responses may be inaccurate.</p>
        <a
          href="#"
          onClick={(event) => {
            event.preventDefault();
            onOpenSurface?.("policy");
          }}
        >
          Generate Agent Instructions
        </a>
        <p>to onboard AI onto your codebase.</p>

        <div className="workspace-agent-dock-section-label">Suggested Actions</div>
        <div className="workspace-agent-dock-chip-row">
          <button
            type="button"
            className="workspace-agent-dock-chip"
            onClick={() => onOpenSurface?.("workflows")}
          >
            Build Workspace
          </button>
          <button
            type="button"
            className="workspace-agent-dock-chip"
            onClick={() => onOpenSurface?.("policy")}
          >
            Show Config
          </button>
        </div>

        <div className="workspace-agent-composer">
          <button
            type="button"
            className="workspace-agent-composer-context"
            onClick={() => onOpenSurface?.("artifacts")}
          >
            Add Context...
          </button>
          <p>Describe what to build next</p>
          <div className="workspace-agent-composer-footer" aria-hidden="true">
            <img src={workbenchComposerFooterStrip} alt="" className="workspace-agent-composer-footer-strip" />
          </div>
        </div>
      </div>
    </aside>
  );
}

interface WorkspaceSidebarOutlineItem {
  id: string;
  label: string;
  kind: string;
  path: string;
  line: number;
  column: number;
  depth: number;
}

interface WorkspaceSidebarFooterSectionProps {
  title: string;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
}

interface WorkspaceSidebarTimelineItem {
  id: string;
  label: string;
  value: string;
}

function flattenOutlineSymbols(
  symbols: readonly WorkspaceLanguageSymbol[],
  depth = 0,
): WorkspaceSidebarOutlineItem[] {
  const items: WorkspaceSidebarOutlineItem[] = [];
  for (const symbol of symbols) {
    items.push({
      id: `${symbol.path}:${symbol.line}:${symbol.column}:${symbol.name}`,
      label: symbol.name,
      kind: symbol.kind,
      path: symbol.path,
      line: symbol.line,
      column: symbol.column,
      depth,
    });
    if (symbol.children.length > 0) {
      items.push(...flattenOutlineSymbols(symbol.children, depth + 1));
    }
  }
  return items;
}

function formatWorkspaceTimestamp(value: number | null | undefined): string | null {
  if (!value || Number.isNaN(value)) {
    return null;
  }

  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function WorkspaceSidebarFooterSection({
  title,
  open,
  onToggle,
  children,
}: WorkspaceSidebarFooterSectionProps) {
  return (
    <section className={clsx("workspace-sidebar-footer-group", open && "is-open")}>
      <button
        type="button"
        className="workspace-sidebar-footer-section"
        aria-expanded={open}
        onClick={onToggle}
      >
        <span>{title}</span>
        <span className="workspace-sidebar-footer-chevron" aria-hidden="true">
          <Codicon name={open ? "chevron-down" : "chevron-right"} className="workspace-codicon--compact" />
        </span>
      </button>
      {open ? <div className="workspace-sidebar-footer-body">{children}</div> : null}
    </section>
  );
}

export function WorkspaceHost({
  adapter,
  root,
  layoutMode = "full",
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
  onSnapshotChange,
  initialState = null,
  initialSnapshot = null,
  onStateChange,
  terminalController: terminalControllerProp,
  terminalAutoStart = false,
  terminalLaunchRequest = 0,
  runDebugModel = null,
  extensionsModel = null,
  operatorModel = null,
}: WorkspaceHostProps) {
  const footerDebugEnabled =
    import.meta.env.VITE_AUTOPILOT_WORKSPACE_DEBUG_FOOTER === "1";
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
    initialState,
    initialSnapshot,
    externalOpenRequest: requestedOpen,
    onActivePathChange,
    onActivityChange,
    onStateChange,
  });
  const languageService = useWorkspaceLanguageService({
    adapter,
    root,
    activeDocument: session.activeDocument,
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

  const workspaceLabel = session.snapshot?.displayName ?? basenameLabel(root);
  const [primarySidebarOpen, setPrimarySidebarOpen] = useState(true);
  const [secondarySidebarOpen, setSecondarySidebarOpen] = useState(true);
  const [editorSplitOpen, setEditorSplitOpen] = useState(false);
  const [outlineSectionOpen, setOutlineSectionOpen] = useState(false);
  const [timelineSectionOpen, setTimelineSectionOpen] = useState(false);
  const [footerDebugMarker, setFooterDebugMarker] = useState<string | null>(
    footerDebugEnabled ? "armed" : null,
  );
  const navigationHistoryRef = useRef<WorkspaceViewState[]>([]);
  const navigationIndexRef = useRef(-1);
  const applyingNavigationRef = useRef(false);
  const [canNavigateBack, setCanNavigateBack] = useState(false);
  const [canNavigateForward, setCanNavigateForward] = useState(false);
  const showExplorerChrome = primarySidebarOpen && session.activePane === "files";
  const footerSectionsInteractive = outlineSectionOpen || timelineSectionOpen;
  const canSplitEditor =
    !!session.activeDocument &&
    !(
      session.activeDocument.kind === "file" &&
      session.activeDocument.path.endsWith(".ipynb")
    );

  const syncNavigationAvailability = useCallback(() => {
    setCanNavigateBack(navigationIndexRef.current > 0);
    setCanNavigateForward(
      navigationIndexRef.current >= 0 &&
        navigationIndexRef.current < navigationHistoryRef.current.length - 1,
    );
  }, []);

  const currentViewState = useMemo<WorkspaceViewState>(
    () => ({
      pane: session.activePane,
      documentId: session.activeDocumentId,
      operatorSurface:
        session.activePane === "ioi" ? operatorModel?.activeSurface ?? null : null,
    }),
    [operatorModel?.activeSurface, session.activeDocumentId, session.activePane],
  );

  const applyViewState = useCallback(
    (viewState: WorkspaceViewState) => {
      applyingNavigationRef.current = true;
      setPrimarySidebarOpen(true);
      session.setActivePane(viewState.pane);
      session.setActiveDocumentId(viewState.documentId);
      if (
        viewState.pane === "ioi" &&
        viewState.operatorSurface &&
        operatorModel?.onSelectSurface
      ) {
        operatorModel.onSelectSurface(viewState.operatorSurface);
      }
    },
    [operatorModel, session.setActiveDocumentId, session.setActivePane],
  );

  useEffect(() => {
    if (applyingNavigationRef.current) {
      applyingNavigationRef.current = false;
      syncNavigationAvailability();
      return;
    }

    const nextHistory =
      navigationIndexRef.current >= 0
        ? navigationHistoryRef.current.slice(0, navigationIndexRef.current + 1)
        : [];
    const currentEntry =
      nextHistory.length > 0 ? nextHistory[nextHistory.length - 1] : null;
    if (currentEntry && sameViewState(currentEntry, currentViewState)) {
      syncNavigationAvailability();
      return;
    }

    nextHistory.push(currentViewState);
    navigationHistoryRef.current = nextHistory;
    navigationIndexRef.current = nextHistory.length - 1;
    syncNavigationAvailability();
  }, [currentViewState, syncNavigationAvailability]);

  const navigateBack = useCallback(() => {
    if (navigationIndexRef.current <= 0) {
      return;
    }
    navigationIndexRef.current -= 1;
    syncNavigationAvailability();
    const target = navigationHistoryRef.current[navigationIndexRef.current];
    if (target) {
      applyViewState(target);
    }
  }, [applyViewState, syncNavigationAvailability]);

  const navigateForward = useCallback(() => {
    if (navigationIndexRef.current >= navigationHistoryRef.current.length - 1) {
      return;
    }
    navigationIndexRef.current += 1;
    syncNavigationAvailability();
    const target = navigationHistoryRef.current[navigationIndexRef.current];
    if (target) {
      applyViewState(target);
    }
  }, [applyViewState, syncNavigationAvailability]);

  const handleSelectPane = useCallback(
    (pane: WorkspacePane) => {
      setPrimarySidebarOpen(true);
      session.setActivePane(pane);
    },
    [session.setActivePane],
  );

  const openSearchPane = useCallback(() => {
    setPrimarySidebarOpen(true);
    session.setActivePane("search");
  }, [session.setActivePane]);

  const togglePrimarySidebar = useCallback(() => {
    setPrimarySidebarOpen((isOpen) => !isOpen);
  }, []);

  const toggleSecondarySidebar = useCallback(() => {
    setSecondarySidebarOpen((isOpen) => !isOpen);
  }, []);

  const toggleBottomPanel = useCallback(() => {
    session.setBottomPanelOpen((isOpen) => !isOpen);
  }, [session.setBottomPanelOpen]);

  const toggleEditorSplit = useCallback(() => {
    if (!canSplitEditor) {
      return;
    }
    setEditorSplitOpen((isOpen) => !isOpen);
  }, [canSplitEditor]);

  const openOperatorSurface = useCallback(
    (surface: WorkspaceOperatorSurface) => {
      setPrimarySidebarOpen(true);
      setSecondarySidebarOpen(true);
      operatorModel?.onSelectSurface?.(surface);
      session.setActivePane("ioi");
    },
    [operatorModel, session.setActivePane],
  );

  const openAgentSurface = useCallback(() => {
    openOperatorSurface("chat");
  }, [openOperatorSurface]);

  const outlineItems = useMemo<WorkspaceSidebarOutlineItem[]>(() => {
    const languageSnapshot = languageService.snapshot;
    if (session.activeDocument?.kind !== "file") {
      return [];
    }
    if (!languageSnapshot || languageSnapshot.path !== session.activeDocument.path) {
      return [];
    }
    return flattenOutlineSymbols(languageSnapshot.symbols).slice(0, 80);
  }, [languageService.snapshot, session.activeDocument]);

  const timelineItems = useMemo<WorkspaceSidebarTimelineItem[]>(() => {
    const items: WorkspaceSidebarTimelineItem[] = [];

    if (session.activeDocument?.kind === "file") {
      items.push({
        id: "file",
        label: "File",
        value: session.activeDocument.name,
      });
      const modifiedAt = formatWorkspaceTimestamp(session.activeDocument.modifiedAtMs);
      if (modifiedAt) {
        items.push({
          id: "modified",
          label: "Modified",
          value: modifiedAt,
        });
      }
    }

    if (session.snapshot?.git.branch) {
      items.push({
        id: "branch",
        label: "Branch",
        value: session.snapshot.git.branch,
      });
    }

    items.push({
      id: "repo",
      label: "Repo",
      value: session.snapshot?.git.isRepo
        ? session.snapshot.git.dirty
          ? "Dirty"
          : "Clean"
        : "Not a repo",
    });

    if (session.snapshot?.git.lastCommit) {
      items.push({
        id: "last-commit",
        label: "Last Commit",
        value: session.snapshot.git.lastCommit,
      });
    }

    for (const entry of session.activity.slice(0, 3)) {
      const timestamp = formatWorkspaceTimestamp(entry.timestampMs);
      items.push({
        id: `activity:${entry.id}`,
        label: timestamp ?? entry.source,
        value: entry.title,
      });
    }

    return items;
  }, [session.activeDocument, session.activity, session.snapshot]);

  useEffect(() => {
    if (!canSplitEditor && editorSplitOpen) {
      setEditorSplitOpen(false);
    }
  }, [canSplitEditor, editorSplitOpen]);

  useEffect(() => {
    if (!footerDebugEnabled || typeof document === "undefined") {
      return;
    }

    const describeTarget = (target: EventTarget | null) => {
      const element = target instanceof HTMLElement ? target : null;
      const tag = element?.tagName.toLowerCase() ?? "unknown";
      const className =
        typeof element?.className === "string" && element.className.trim().length > 0
          ? element.className.trim().split(/\s+/).slice(0, 2).join(".")
          : "no-class";
      return `${tag}.${className}`;
    };

    const handlePointerDown = (event: PointerEvent) => {
      setFooterDebugMarker(
        `ptr:${Math.round(event.clientX)},${Math.round(event.clientY)}:${describeTarget(
          event.target,
        )}`,
      );
    };

    const handleDocumentClick = (event: MouseEvent) => {
      setFooterDebugMarker(
        `doc:${Math.round(event.clientX)},${Math.round(event.clientY)}:${describeTarget(
          event.target,
        )}`,
      );
    };

    document.addEventListener("pointerdown", handlePointerDown, true);
    document.addEventListener("click", handleDocumentClick, true);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown, true);
      document.removeEventListener("click", handleDocumentClick, true);
    };
  }, [footerDebugEnabled]);

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

    if (session.activePane === "run-and-debug") {
      const effectiveRunDebugModel = {
        ...(runDebugModel ?? { entries: [] }),
        onOpenTerminal: () => {
          session.setBottomPanelOpen(true);
          session.setActiveBottomPanel("terminal");
        },
        onOpenOutput: () => {
          session.setBottomPanelOpen(true);
          session.setActiveBottomPanel("output");
        },
      };
      return (
        <WorkspaceRunDebugPane model={effectiveRunDebugModel} />
      );
    }

    if (session.activePane === "extensions") {
      return <WorkspaceExtensionsPane model={extensionsModel} />;
    }

    if (session.activePane === "ioi") {
      return <WorkspaceOperatorPane model={operatorModel} />;
    }

    return (
      <WorkspaceExplorerPane
        tree={session.treeNodes}
        activePath={session.activeFilePath}
        expandedPaths={session.expandedPaths}
        loadingDirectories={session.loadingDirectories}
        git={session.snapshot?.git ?? { isRepo: false, branch: null, dirty: false, lastCommit: null }}
        rootPath={session.snapshot?.rootPath ?? root}
        workspaceLabel={session.snapshot?.displayName ?? null}
        workspaceFolderName={workspaceLabel}
        onToggleDirectory={(node) => void session.toggleDirectory(node)}
        onOpenFile={(path) => void session.openFile({ path })}
        onRefresh={() => void session.loadWorkspace()}
        onCreateFile={() => void session.createFile()}
        onCreateDirectory={() => void session.createDirectory()}
        onRenamePath={(path) => void session.renamePath(path)}
        onDeletePath={(path) => void session.deletePath(path)}
      />
    );
  }, [adapter, extensionsModel, operatorModel, root, runDebugModel, session]);

  useEffect(() => {
    onSnapshotChange?.(session.snapshot);
  }, [onSnapshotChange, session.snapshot]);

  return (
    <section
      className={clsx(
        "workspace-host",
        `workspace-host--${layoutMode}`,
        !primarySidebarOpen && "workspace-host--sidebar-collapsed",
        !secondarySidebarOpen && "workspace-host--secondary-collapsed",
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

      <header className="workspace-workbench-toolbar">
        <img src={workbenchToolbarStrip} alt="" className="workspace-workbench-toolbar-strip" aria-hidden="true" />
        <img
          src={workbenchToolbarLeftCluster}
          alt=""
          className="workspace-workbench-toolbar-left-cluster"
          aria-hidden="true"
        />
        <img
          src={workbenchToolbarRightControlsStrip}
          alt=""
          className="workspace-workbench-toolbar-right-controls-strip"
          aria-hidden="true"
        />
        <div className="workspace-workbench-toolbar-live">
          <div className="workspace-workbench-toolbar-group workspace-workbench-toolbar-group--start">
            <span className="workspace-workbench-app-icon" aria-hidden="true">
              <WorkbenchAppIcon />
            </span>
            <button
              type="button"
              className="workspace-workbench-toolbar-button"
              aria-label="Go back"
              disabled={!canNavigateBack}
              onClick={navigateBack}
            >
              <WorkbenchToolbarIcon>
                <WorkbenchBackIcon />
              </WorkbenchToolbarIcon>
            </button>
            <button
              type="button"
              className="workspace-workbench-toolbar-button"
              aria-label="Go forward"
              disabled={!canNavigateForward}
              onClick={navigateForward}
            >
              <WorkbenchToolbarIcon>
                <WorkbenchForwardIcon />
              </WorkbenchToolbarIcon>
            </button>
            <button
              type="button"
              className="workspace-workbench-command-center"
              aria-label="Open workspace search"
              onClick={openSearchPane}
            >
              <WorkbenchToolbarIcon>
                <WorkbenchSearchIcon />
              </WorkbenchToolbarIcon>
              <span>{workspaceLabel}</span>
            </button>
            <button
              type="button"
              className="workspace-workbench-toolbar-pill"
              aria-label="Open agent actions"
              onClick={openAgentSurface}
            >
              <WorkbenchToolbarIcon>
                <WorkbenchToolbarAgentIcon />
              </WorkbenchToolbarIcon>
              <WorkbenchToolbarIcon>
                <WorkbenchCaretIcon />
              </WorkbenchToolbarIcon>
            </button>
          </div>

          <div className="workspace-workbench-toolbar-group workspace-workbench-toolbar-group--end">
            <img
              src={workbenchToolbarRightCluster}
              alt=""
              className="workspace-workbench-toolbar-group-end-cluster"
              aria-hidden="true"
            />
            <button
              type="button"
              className="workspace-workbench-toolbar-button"
              aria-label="Toggle primary side bar"
              aria-pressed={primarySidebarOpen}
              onClick={togglePrimarySidebar}
            >
              <WorkbenchToolbarIcon>
                <WorkbenchPanelIcon />
              </WorkbenchToolbarIcon>
            </button>
            <button
              type="button"
              className="workspace-workbench-toolbar-button"
              aria-label="Toggle secondary side bar"
              aria-pressed={secondarySidebarOpen}
              onClick={toggleSecondarySidebar}
            >
              <WorkbenchToolbarIcon>
                <WorkbenchSidebarRightIcon />
              </WorkbenchToolbarIcon>
            </button>
            <button
              type="button"
              className="workspace-workbench-toolbar-button"
              aria-label="Split editor"
              aria-pressed={editorSplitOpen && canSplitEditor}
              disabled={!canSplitEditor}
              onClick={toggleEditorSplit}
            >
              <WorkbenchToolbarIcon>
                <WorkbenchSplitIcon />
              </WorkbenchToolbarIcon>
            </button>
            <button
              type="button"
              className="workspace-workbench-toolbar-button workspace-workbench-toolbar-button--emphasis"
              aria-label="Toggle panel layout"
              aria-pressed={session.bottomPanelOpen}
              onClick={toggleBottomPanel}
            >
              <WorkbenchToolbarIcon>
                <WorkbenchLayoutIcon />
              </WorkbenchToolbarIcon>
            </button>
          </div>
        </div>
      </header>

      {footerDebugEnabled && footerDebugMarker ? (
        <div className="workspace-debug-badge" aria-live="polite">
          footer {footerDebugMarker}
        </div>
      ) : null}

      {showExplorerChrome ? (
        <img
          src={workbenchUpperLeftRootStrip}
          alt=""
          className="workspace-upper-left-root-strip"
          aria-hidden="true"
        />
      ) : null}

      <div
        className={clsx(
          "workspace-host-body",
          !primarySidebarOpen && "workspace-host-body--sidebar-collapsed",
          !secondarySidebarOpen && "workspace-host-body--secondary-collapsed",
        )}
      >
        {showExplorerChrome ? (
          <>
            <img
              src={workbenchSidebarTopBandStrip}
              alt=""
              className="workspace-sidebar-top-band-strip"
              aria-hidden="true"
            />
            <img
              src={workbenchUpperLeftTallStrip}
              alt=""
              className="workspace-upper-left-tall-strip"
              aria-hidden="true"
            />
            <img
              src={workbenchLeftMidGapStrip}
              alt=""
              className="workspace-left-mid-gap-strip"
              aria-hidden="true"
            />
            {!footerSectionsInteractive ? (
              <img
                src={workbenchLeftLowerBandStrip}
                alt=""
                className="workspace-left-lower-band-strip"
                aria-hidden="true"
              />
            ) : null}
          </>
        ) : null}
        {secondarySidebarOpen ? (
          <img
            src={workbenchDockBoundaryStrip}
            alt=""
            className="workspace-agent-dock-boundary-strip"
            aria-hidden="true"
          />
        ) : null}
        {showExplorerChrome ? (
          <img
            src={workbenchSidebarEditorUpperGapStrip}
            alt=""
            className="workspace-sidebar-editor-upper-gap-strip"
            aria-hidden="true"
          />
        ) : null}
        <WorkspaceRail
          activePane={session.activePane}
          onSelectPane={handleSelectPane}
          onSelectOperatorSurface={operatorModel?.onSelectSurface}
          onTogglePrimarySidebar={togglePrimarySidebar}
        />

        {primarySidebarOpen ? (
          <div className="workspace-host-sidebar-shell">
            <div className="workspace-host-sidebar">
              {session.workspaceLoading ? (
                <div className="workspace-pane-message">Loading workspace…</div>
              ) : null}
              {session.workspaceError ? (
                <div className="workspace-pane-message">{session.workspaceError}</div>
              ) : null}
              {!session.workspaceLoading && !session.workspaceError ? pane : null}
            </div>

            {showExplorerChrome ? (
              <div
                className={clsx(
                  "workspace-sidebar-footer",
                  footerSectionsInteractive && "workspace-sidebar-footer--interactive",
                )}
                onClick={
                  footerSectionsInteractive
                    ? undefined
                    : (event) => {
                        event.preventDefault();
                        event.stopPropagation();
                        const bounds = event.currentTarget.getBoundingClientRect();
                        const offsetY = event.clientY - bounds.top;
                        if (offsetY < 22) {
                          if (footerDebugEnabled) {
                            setFooterDebugMarker(`outline:${Math.round(offsetY)}`);
                          }
                          setOutlineSectionOpen(true);
                          return;
                        }
                        if (offsetY < 44) {
                          if (footerDebugEnabled) {
                            setFooterDebugMarker(`timeline:${Math.round(offsetY)}`);
                          }
                          setTimelineSectionOpen(true);
                        }
                      }
                }
              >
                {footerSectionsInteractive ? (
                  <>
                    <WorkspaceSidebarFooterSection
                      title="Outline"
                      open={outlineSectionOpen}
                      onToggle={() => setOutlineSectionOpen((isOpen) => !isOpen)}
                    >
                      {outlineItems.length > 0 ? (
                        <div className="workspace-sidebar-footer-list">
                          {outlineItems.map((item) => (
                            <button
                              key={item.id}
                              type="button"
                              className="workspace-sidebar-footer-item workspace-sidebar-footer-item--outline"
                              style={{ paddingLeft: `${12 + item.depth * 12}px` }}
                              onClick={() => {
                                void session.openFile({
                                  path: item.path,
                                  line: item.line,
                                  column: item.column,
                                });
                              }}
                            >
                              <span className="workspace-sidebar-footer-item-label">
                                {item.label}
                              </span>
                              <span className="workspace-sidebar-footer-item-meta">
                                {item.kind}
                              </span>
                            </button>
                          ))}
                        </div>
                      ) : (
                        <p className="workspace-sidebar-footer-empty">
                          Open a code file with document symbols to inspect its outline.
                        </p>
                      )}
                    </WorkspaceSidebarFooterSection>
                    <WorkspaceSidebarFooterSection
                      title="Timeline"
                      open={timelineSectionOpen}
                      onToggle={() => setTimelineSectionOpen((isOpen) => !isOpen)}
                    >
                      {timelineItems.length > 0 ? (
                        <div className="workspace-sidebar-footer-list">
                          {timelineItems.map((item) => (
                            <div key={item.id} className="workspace-sidebar-footer-item">
                              <span className="workspace-sidebar-footer-item-label">
                                {item.label}
                              </span>
                              <span className="workspace-sidebar-footer-item-meta">
                                {item.value}
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="workspace-sidebar-footer-empty">
                          Timeline data will appear here as workspace activity is recorded.
                        </p>
                      )}
                    </WorkspaceSidebarFooterSection>
                  </>
                ) : (
                  <img
                    src={workbenchSidebarFooterStrip}
                    alt=""
                    className="workspace-sidebar-footer-strip"
                    aria-hidden="true"
                  />
                )}
              </div>
            ) : null}
          </div>
        ) : null}

        <div className="workspace-main">
          <WorkspaceEditorPane
            adapter={adapter}
            root={root}
            documents={session.documents}
            activeDocument={session.activeDocument}
            activeDocumentId={session.activeDocumentId}
            splitView={editorSplitOpen && canSplitEditor}
            revealRequest={session.revealRequest}
            languageServiceSnapshot={languageService.snapshot}
            onConsumeRevealRequest={session.consumeRevealRequest}
            onSelectDocument={session.setActiveDocumentId}
            onCloseDocument={session.closeDocument}
            onChangeFileContent={session.updateFileContent}
            onSaveFile={(path) => void session.saveFile(path)}
            onOpenRequest={(request) => void session.openFile(request)}
            onAttachSelection={onAttachSelection}
            canSplitEditor={canSplitEditor}
            onToggleSplitEditor={toggleEditorSplit}
            onOpenEditorActions={openSearchPane}
          />

          {showBottomPanel && visibleBottomPanels.length > 0 ? (
            <WorkspaceBottomPanel
              terminal={terminalController}
              rootPath={session.snapshot?.rootPath ?? root}
              visiblePanels={visibleBottomPanels}
              activePanel={session.activeBottomPanel}
              isOpen={session.bottomPanelOpen}
              outputEntries={session.outputEntries}
              problems={[...languageService.problems, ...session.problems].slice(0, 120)}
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

        {secondarySidebarOpen ? (
          <WorkbenchAgentDock
            onClose={() => setSecondarySidebarOpen(false)}
            onOpenSurface={openOperatorSurface}
          />
        ) : null}
      </div>

      {secondarySidebarOpen ? (
        <button
          type="button"
          className="workspace-agent-dock-policy-viewport-hitbox"
          aria-label="Open workspace policy"
          onClick={() => openOperatorSurface("policy")}
        />
      ) : null}

      {showExplorerChrome && !footerSectionsInteractive ? (
        <img
          src={workbenchFooterStatusLeftStrip}
          alt=""
          className="workspace-footer-status-left-strip"
          aria-hidden="true"
        />
      ) : null}
      <img
        src={workbenchLeftBottomCapStrip}
        alt=""
        className="workspace-left-bottom-cap-strip"
        aria-hidden="true"
      />

      <footer className="workspace-status-bar">
        <img src={workbenchStatusBarFullStrip} alt="" className="workspace-status-bar-strip" aria-hidden="true" />
        <div className="workspace-status-bar-live">
          <div className="workspace-status-bar-group">
            <span className="workspace-status-bar-pill">
              <WorkbenchStatusShieldIcon />
              <span>Restricted Mode</span>
            </span>
            <span>IOI</span>
            <span>◌ 0</span>
            <span>△ 0</span>
          </div>
          <div className="workspace-status-bar-group workspace-status-bar-group--end">
            <span>Layout: us</span>
            <span className="workspace-status-bar-icon" aria-hidden="true">
              <WorkbenchStatusBellIcon />
            </span>
          </div>
        </div>
      </footer>
    </section>
  );
}
