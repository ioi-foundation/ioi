import clsx from "clsx";
import { ArrowLeft } from "lucide-react";
import {
  createElement,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type ComponentType,
} from "react";
import {
  WorkspaceHost,
  type WorkspaceExtensionsModel,
  type WorkspaceOperatorModel,
  type WorkspaceOperatorSurface,
  type WorkspacePersistedState,
  type WorkspaceRunDebugModel,
  type WorkspaceSnapshot,
} from "@ioi/workspace-substrate";

import type { TauriRuntime } from "../../services/TauriRuntime";
import {
  loadWorkspaceShellState,
  persistWorkspaceShellState,
} from "../../services/workspaceShellState";
import { OpenVsCodeDirectSurface } from "./OpenVsCodeDirectSurface";
import {
  createExtensionsModel,
  createOperatorModel,
  createRunDebugModel,
  loadDirectWorkspaceWorkbenchData,
  type DirectWorkspaceBridgeState,
} from "../../services/workspaceDirectWorkbenchModel";
import type {
  WorkspaceWorkbenchHost,
  WorkspaceWorkbenchProjectDescriptor,
} from "../../services/workspaceWorkbenchHost";
import { useWorkspaceWorkbenchSession } from "../../services/useWorkspaceWorkbenchSession";
import { tauriWorkspaceAdapter } from "../../services/workspaceAdapter";
import {
  createUniqueRepositorySlug,
  getGeneratedRepositoryPath,
  loadWorkspaceRepositories,
  markWorkspaceRepositoryOpened,
  persistCreatedWorkspaceRepository,
  toggleWorkspaceRepositoryFavorite,
  type WorkspaceRepositoryRecord,
} from "../../services/workspaceRepositoryRegistry";
import {
  WorkspaceRepositoryGate,
  type WorkspaceRepositoryCreateRequest,
} from "./WorkspaceRepositoryGate";

interface WorkspaceShellProps {
  active: boolean;
  currentProject: WorkspaceWorkbenchProjectDescriptor;
  projects?: WorkspaceWorkbenchProjectDescriptor[];
  runtime: TauriRuntime;
  host: WorkspaceWorkbenchHost;
  fullBleed?: boolean;
}

type WorkspaceShellMode = "repository-gate" | "workbench";

type ShellIconProps = {
  size?: number;
  "aria-hidden"?: boolean | "true" | "false";
};

function renderShellIcon(Icon: unknown, props: ShellIconProps = {}) {
  return createElement(Icon as ComponentType<ShellIconProps>, props);
}

function defaultWorkspaceShellState(): WorkspacePersistedState {
  return {
    activePane: "files",
    activeBottomPanel: "output",
    bottomPanelOpen: false,
    expandedPaths: {},
    documents: [],
    activeDocumentPath: null,
  };
}

export function WorkspaceShell({
  active,
  currentProject,
  projects,
  runtime,
  host,
  fullBleed = false,
}: WorkspaceShellProps) {
  const seedProjects = useMemo(
    () => (projects && projects.length > 0 ? projects : [currentProject]),
    [currentProject, projects],
  );
  const [shellMode, setShellMode] =
    useState<WorkspaceShellMode>("repository-gate");
  const [repositories, setRepositories] = useState(() =>
    loadWorkspaceRepositories(seedProjects),
  );
  const [selectedRepository, setSelectedRepository] =
    useState<WorkspaceRepositoryRecord | null>(null);
  const [creatingRepository, setCreatingRepository] = useState(false);
  const [createRepositoryError, setCreateRepositoryError] = useState<string | null>(
    null,
  );
  const workbenchProject = selectedRepository ?? currentProject;
  const workbenchActive =
    active && shellMode === "workbench" && selectedRepository !== null;

  const refreshRepositories = useCallback(() => {
    setRepositories(loadWorkspaceRepositories(seedProjects));
  }, [seedProjects]);

  useEffect(() => {
    refreshRepositories();
  }, [refreshRepositories]);

  const openRepository = useCallback(
    async (repository: WorkspaceRepositoryRecord) => {
      if (repository.source === "created") {
        await tauriWorkspaceAdapter.createDirectory(".", repository.rootPath);
      }

      markWorkspaceRepositoryOpened(repository.id);
      const nextRepositories = loadWorkspaceRepositories(seedProjects);
      setRepositories(nextRepositories);
      setSelectedRepository(
        nextRepositories.find(
          (nextRepository) => nextRepository.id === repository.id,
        ) ?? repository,
      );
      setCreateRepositoryError(null);
      setShellMode("workbench");
    },
    [seedProjects],
  );

  const toggleRepositoryFavorite = useCallback(
    (repository: WorkspaceRepositoryRecord) => {
      toggleWorkspaceRepositoryFavorite(repository.id);
      refreshRepositories();
    },
    [refreshRepositories],
  );

  const createRepository = useCallback(
    async (request: WorkspaceRepositoryCreateRequest) => {
      setCreatingRepository(true);
      setCreateRepositoryError(null);

      try {
        const slug = createUniqueRepositorySlug(
          request.name,
          repositories.map((repository) => repository.rootPath),
        );
        const rootPath = getGeneratedRepositoryPath(slug);

        await tauriWorkspaceAdapter.createDirectory(".", rootPath);

        const now = Date.now();
        const repository: WorkspaceRepositoryRecord = {
          id: `created:${rootPath}`,
          name: request.name,
          description: `${request.categoryLabel} / ${request.templateLabel}`,
          environment: "Local",
          rootPath,
          source: "created",
          category: request.category,
          template: request.template,
          createdAtMs: now,
          lastOpenedAtMs: now,
          favorite: false,
        };

        persistCreatedWorkspaceRepository(repository);
        setCreatingRepository(false);
        await openRepository(repository);
      } catch (error) {
        setCreatingRepository(false);
        setCreateRepositoryError(
          error instanceof Error
            ? error.message
            : "The repository folder could not be created.",
        );
      }
    },
    [openRepository, repositories],
  );

  const {
    status,
    session,
    error,
    surfaceReady,
    surface,
    bootPhase,
    markSurfaceReady,
    restartWorkspace,
  } = useWorkspaceWorkbenchSession({
    active: workbenchActive,
    enabled: workbenchActive,
    currentProject: workbenchProject,
    runtime,
    host,
  });
  const sessionDescriptor = session ? host.describeSession(session) : null;
  const [persistedState, setPersistedState] = useState(() =>
    loadWorkspaceShellState(workbenchProject.rootPath),
  );
  const [surfaceError, setSurfaceError] = useState<string | null>(null);
  const [bridgeState, setBridgeState] = useState<DirectWorkspaceBridgeState | null>(null);
  const [extensionManifests, setExtensionManifests] = useState<
    Awaited<ReturnType<typeof loadDirectWorkspaceWorkbenchData>>["extensionManifests"]
  >([]);

  useEffect(() => {
    setPersistedState(loadWorkspaceShellState(workbenchProject.rootPath));
  }, [workbenchProject.rootPath]);

  useEffect(() => {
    setSurfaceError(null);
  }, [surface?.key]);

  const initialWorkspaceState = useMemo<WorkspacePersistedState | null>(
    () => persistedState?.shellState ?? defaultWorkspaceShellState(),
    [persistedState],
  );
  const initialWorkspaceSnapshot = persistedState?.snapshot ?? null;
  const activeOperatorSurface: WorkspaceOperatorSurface =
    persistedState?.dockSurface ?? "chat";

  const substratePreviewSurfaceVisible = Boolean(
    surface && surface.kind === "substrate-preview",
  );
  const effectiveError = error ?? surfaceError;
  const overlayVisible =
    Boolean(effectiveError) ||
    status !== "ready" ||
    (!substratePreviewSurfaceVisible && !surfaceReady);

  useEffect(() => {
    if (!import.meta.env.DEV || !workbenchActive) {
      return;
    }
    console.info("[WorkspaceBoot] shell state", {
      rootPath: workbenchProject.rootPath,
      status,
      surfaceKind: surface?.kind ?? null,
      surfaceReady,
      overlayVisible,
      error,
    });
  }, [
    error,
    overlayVisible,
    status,
    surface,
    surfaceReady,
    workbenchActive,
    workbenchProject.rootPath,
  ]);

  const persistShellState = (
    nextShellState: WorkspacePersistedState | null,
    nextActivePath?: string | null,
  ) => {
    setPersistedState((current) => {
      const nextState = {
        dockSurface: current?.dockSurface ?? "chat",
        shellState: nextShellState,
        lastActivePath:
          nextActivePath === undefined
            ? (current?.lastActivePath ?? null)
            : nextActivePath,
        snapshot: current?.snapshot ?? null,
      };
      persistWorkspaceShellState(workbenchProject.rootPath, nextState);
      return nextState;
    });
  };

  const persistOperatorSurface = (dockSurface: WorkspaceOperatorSurface) => {
    setPersistedState((current) => {
      const nextState = {
        dockSurface,
        shellState: current?.shellState ?? initialWorkspaceState,
        lastActivePath: current?.lastActivePath ?? null,
        snapshot: current?.snapshot ?? initialWorkspaceSnapshot,
      };
      persistWorkspaceShellState(workbenchProject.rootPath, nextState);
      return nextState;
    });
  };

  const persistSnapshot = (nextSnapshot: WorkspaceSnapshot | null) => {
    setPersistedState((current) => {
      const nextState = {
        dockSurface: current?.dockSurface ?? "chat",
        shellState: current?.shellState ?? initialWorkspaceState,
        lastActivePath: current?.lastActivePath ?? null,
        snapshot: nextSnapshot,
      };
      persistWorkspaceShellState(workbenchProject.rootPath, nextState);
      return nextState;
    });
  };

  useEffect(() => {
    if (
      !workbenchActive ||
      !session ||
      !surface ||
      surface.kind !== "substrate-preview"
    ) {
      setBridgeState(null);
      setExtensionManifests([]);
      return;
    }

    let cancelled = false;
    let intervalHandle: number | null = null;

    const refresh = async () => {
      try {
        const next = await loadDirectWorkspaceWorkbenchData({
          runtime,
          host,
          currentProject: workbenchProject,
          session,
        });
        if (cancelled) {
          return;
        }
        setBridgeState(next.bridgeState);
        setExtensionManifests(next.extensionManifests);
      } catch (error) {
        if (!cancelled) {
          console.error("[Workspace] Failed to load direct workbench model:", error);
        }
      }
    };

    void refresh();
    intervalHandle = window.setInterval(refresh, 12_000);

    return () => {
      cancelled = true;
      if (intervalHandle !== null) {
        window.clearInterval(intervalHandle);
      }
    };
  }, [host, runtime, session, surface, workbenchActive, workbenchProject]);

  const activeFilePath = persistedState?.lastActivePath ?? null;

  const runDebugModel = useMemo<WorkspaceRunDebugModel>(
    () =>
      createRunDebugModel({
        bridgeState,
        runtime,
        rootPath: workbenchProject.rootPath,
        activeFilePath,
      }),
    [activeFilePath, bridgeState, runtime, workbenchProject.rootPath],
  );

  const extensionsModel = useMemo<WorkspaceExtensionsModel>(
    () =>
      createExtensionsModel({
        bridgeState,
        extensionManifests,
        runtime,
      }),
    [bridgeState, extensionManifests, runtime],
  );

  const operatorModel = useMemo<WorkspaceOperatorModel>(
    () =>
      createOperatorModel({
        bridgeState,
        activeSurface: activeOperatorSurface,
        onSelectSurface: persistOperatorSurface,
        runtime,
        rootPath: workbenchProject.rootPath,
        activeFilePath,
      }),
    [
      activeFilePath,
      activeOperatorSurface,
      bridgeState,
      runtime,
      workbenchProject.rootPath,
    ],
  );

  const returnToRepositoryGate = () => {
    setShellMode("repository-gate");
    setSelectedRepository(null);
    setSurfaceError(null);
  };

  return (
    <section
      className={clsx(
        "chat-workspace-oss-shell",
        active && "is-active",
        fullBleed && "is-full-bleed",
      )}
      aria-label="Workspace"
      aria-hidden={!active}
    >
      {shellMode === "repository-gate" ? (
        <WorkspaceRepositoryGate
          repositories={repositories}
          createError={createRepositoryError}
          creating={creatingRepository}
          onCreateRepository={createRepository}
          onOpenRepository={openRepository}
          onToggleFavorite={toggleRepositoryFavorite}
        />
      ) : (
        <div className="chat-workspace-oss-shell__workbench">
          <header className="chat-workspace-oss-shell__workbench-header">
            <button
              type="button"
              className="chat-workspace-oss-shell__back"
              onClick={returnToRepositoryGate}
            >
              {renderShellIcon(ArrowLeft, { size: 15, "aria-hidden": true })}
              <span>Code repositories</span>
            </button>
            <div className="chat-workspace-oss-shell__workbench-title">
              <strong>{workbenchProject.name}</strong>
              <code>{workbenchProject.rootPath}</code>
            </div>
          </header>

          <div className="chat-workspace-oss-shell__workbench-surface">
            {session && surface ? (
              surface.kind === "frame" ? (
                <iframe
                  key={surface.key}
                  className={clsx(
                    "chat-workspace-oss-shell__frame",
                    surfaceReady && "is-ready",
                  )}
                  title={surface.title}
                  src={surface.src}
                  onLoad={() => {
                    markSurfaceReady();
                  }}
                />
              ) : surface.kind === "openvscode-direct" ? (
                <OpenVsCodeDirectSurface
                  key={surface.key}
                  active={workbenchActive}
                  surface={surface}
                  onReady={markSurfaceReady}
                  onError={setSurfaceError}
                />
              ) : (
                <WorkspaceHost
                  key={surface.key}
                  className="chat-workspace-host"
                  adapter={surface.adapter}
                  root={surface.rootPath}
                  layoutMode={surface.layoutMode}
                  defaultPane={surface.defaultPane}
                  title={surface.title}
                  showHeader={surface.showHeader}
                  showBottomPanel={surface.showBottomPanel}
                  initialSnapshot={
                    surface.initialSnapshot ?? initialWorkspaceSnapshot
                  }
                  initialState={initialWorkspaceState}
                  runDebugModel={runDebugModel}
                  extensionsModel={extensionsModel}
                  operatorModel={operatorModel}
                  onStateChange={(nextState) => {
                    persistShellState(nextState);
                  }}
                  onSnapshotChange={persistSnapshot}
                  onActivePathChange={(path) => {
                    persistShellState(
                      persistedState?.shellState ?? initialWorkspaceState,
                      path,
                    );
                  }}
                />
              )
            ) : null}

            {overlayVisible ? (
              <div className="chat-workspace-oss-shell__overlay">
                <div className="chat-workspace-oss-shell__overlay-card">
                  <span className="chat-workspace-oss-shell__eyebrow">
                    {sessionDescriptor?.startupEyebrow ?? "Workspace runtime"}
                  </span>
                  <h2>{workbenchProject.name}</h2>
                  <p>
                    {effectiveError
                      ? (sessionDescriptor?.startupFailureDescription ??
                        "The workspace runtime did not start cleanly.")
                      : (sessionDescriptor?.startupDescription ??
                        "Starting the workspace runtime for this workspace.")}
                  </p>
                  <div className="chat-workspace-oss-shell__meta">
                    <span>Root</span>
                    <code>{workbenchProject.rootPath}</code>
                  </div>
                  {session ? (
                    <div className="chat-workspace-oss-shell__meta">
                      <span>Runtime</span>
                      <code>{sessionDescriptor?.runtimeLabel}</code>
                    </div>
                  ) : null}
                  {import.meta.env.DEV ? (
                    <>
                      <div className="chat-workspace-oss-shell__meta">
                        <span>Debug</span>
                        <code>
                          {`status=${status} session=${session ? "yes" : "no"} surface=${surface?.kind ?? "none"}`}
                        </code>
                      </div>
                      <div className="chat-workspace-oss-shell__meta">
                        <span>Flags</span>
                        <code>
                          {`surfaceReady=${surfaceReady} overlay=${overlayVisible ? "yes" : "no"}`}
                        </code>
                      </div>
                      <div className="chat-workspace-oss-shell__meta">
                        <span>Phase</span>
                        <code>{bootPhase}</code>
                      </div>
                    </>
                  ) : null}
                  {effectiveError ? (
                    <pre className="chat-workspace-oss-shell__error">
                      {effectiveError}
                    </pre>
                  ) : (
                    <div
                      className="chat-workspace-oss-shell__spinner"
                      aria-hidden="true"
                    />
                  )}
                  <div className="chat-workspace-oss-shell__actions">
                    <button
                      type="button"
                      className="chat-workspace-oss-shell__button"
                      onClick={() => {
                        setSurfaceError(null);
                        restartWorkspace();
                      }}
                    >
                      {effectiveError
                        ? "Retry workspace runtime"
                        : "Force reveal now"}
                    </button>
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}
