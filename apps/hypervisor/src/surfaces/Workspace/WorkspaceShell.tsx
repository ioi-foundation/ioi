import clsx from "clsx";
import { ArrowLeft } from "lucide-react";
import { workflowRuntimeUnavailableCopy } from "@ioi/hypervisor-workbench";
import {
  createElement,
  useCallback,
  useEffect,
  useMemo,
  useState,
  type CSSProperties,
  type ComponentType,
  type ReactNode,
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

import type { HypervisorClientRuntime } from "../../services/HypervisorClientRuntime";
import {
  loadWorkspaceShellState,
  persistWorkspaceShellState,
} from "../../services/workspaceShellState";
import {
  createExtensionsModel,
  createOperatorModel,
  createRunDebugModel,
  loadDirectWorkspaceWorkbenchData,
  type DirectWorkspaceAdapterState,
} from "../../services/workspaceDirectWorkbenchModel";
import type {
  WorkspaceWorkbenchHost,
  WorkspaceWorkbenchProjectDescriptor,
} from "../../services/workspaceWorkbenchHost";
import { useWorkspaceWorkbenchSession } from "../../services/useWorkspaceWorkbenchSession";
import { hostWorkspaceAdapter } from "../../services/workspaceAdapter";
import {
  createUniqueRepositorySlug,
  consumePendingWorkspaceRepositoryOpen,
  formatWorkspaceRepositoryMutationError,
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
  runtime: HypervisorClientRuntime;
  host: WorkspaceWorkbenchHost;
  fullBleed?: boolean;
  operatorChatPane?: ReactNode;
  operatorChatPaneWidthPx?: number;
}

type WorkspaceShellMode = "repository-gate" | "workbench";
interface OpenRepositoryOptions {
  ensureDirectory?: boolean;
}

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
  operatorChatPane = null,
  operatorChatPaneWidthPx = 360,
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
  const [createRepositoryError, setCreateRepositoryError] = useState<
    string | null
  >(null);
  const [createdRepositoryNotice, setCreatedRepositoryNotice] =
    useState<WorkspaceRepositoryRecord | null>(null);
  const workbenchProject = selectedRepository ?? currentProject;
  const workbenchActive = active && shellMode === "workbench";

  const refreshRepositories = useCallback(() => {
    setRepositories(loadWorkspaceRepositories(seedProjects));
  }, [seedProjects]);

  useEffect(() => {
    refreshRepositories();
  }, [refreshRepositories]);

  const openRepository = useCallback(
    async (
      repository: WorkspaceRepositoryRecord,
      options: OpenRepositoryOptions = {},
    ) => {
      const ensureDirectory = options.ensureDirectory ?? true;
      if (repository.source === "created" && ensureDirectory) {
        await hostWorkspaceAdapter.createDirectory(".", repository.rootPath);
      }

      markWorkspaceRepositoryOpened(repository.id);
      const nextRepositories = loadWorkspaceRepositories(seedProjects);
      setRepositories(nextRepositories);
      setSelectedRepository(
        nextRepositories.find(
          (nextRepository) => nextRepository.id === repository.id,
        ) ?? repository,
      );
      setCreatedRepositoryNotice(null);
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

  useEffect(() => {
    if (!active) {
      return;
    }

    const pendingRepository =
      consumePendingWorkspaceRepositoryOpen(seedProjects);
    if (!pendingRepository) {
      return;
    }

    void openRepository(pendingRepository, {
      ensureDirectory: false,
    });
  }, [active, openRepository, seedProjects]);

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

        await hostWorkspaceAdapter.createDirectory(".", rootPath);

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
        setRepositories(loadWorkspaceRepositories(seedProjects));
        setCreatedRepositoryNotice(repository);
        setCreatingRepository(false);
        setCreateRepositoryError(null);
      } catch (error) {
        setCreatingRepository(false);
        setCreateRepositoryError(formatWorkspaceRepositoryMutationError(error));
      }
    },
    [repositories, seedProjects],
  );

  const {
    status,
    session,
    error,
    surfaceReady,
    surface,
    bootPhase,
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
  const [adapterState, setAdapterState] =
    useState<DirectWorkspaceAdapterState | null>(null);
  const [extensionManifests, setExtensionManifests] = useState<
    Awaited<
      ReturnType<typeof loadDirectWorkspaceWorkbenchData>
    >["extensionManifests"]
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

  const surfaceKind = surface?.kind ?? null;
  const substratePreviewSurfaceVisible = surfaceKind === "substrate-preview";
  const showOperatorChatPane = Boolean(operatorChatPane);
  const surfaceRuntimeError = useMemo(
    () =>
      surfaceError
        ? workflowRuntimeUnavailableCopy(surfaceError, "workspace_runtime")
        : null,
    [surfaceError],
  );
  const blockingError = error ?? surfaceRuntimeError;
  const workspaceSurfaceReadyEnough =
    Boolean(surface) && (substratePreviewSurfaceVisible || surfaceReady);
  const overlayVisible =
    Boolean(blockingError) ||
    status !== "ready" ||
    !workspaceSurfaceReadyEnough;

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
      error: blockingError,
    });
  }, [
    blockingError,
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
      setAdapterState(null);
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
        setAdapterState(next.adapterState);
        setExtensionManifests(next.extensionManifests);
      } catch (error) {
        if (!cancelled) {
          console.error(
            "[Workspace] Failed to load direct workbench model:",
            error,
          );
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
        adapterState,
        runtime,
        rootPath: workbenchProject.rootPath,
        activeFilePath,
      }),
    [activeFilePath, adapterState, runtime, workbenchProject.rootPath],
  );

  const extensionsModel = useMemo<WorkspaceExtensionsModel>(
    () =>
      createExtensionsModel({
        adapterState,
        extensionManifests,
        runtime,
      }),
    [adapterState, extensionManifests, runtime],
  );

  const operatorModel = useMemo<WorkspaceOperatorModel>(
    () =>
      createOperatorModel({
        adapterState,
        activeSurface: activeOperatorSurface,
        onSelectSurface: persistOperatorSurface,
        runtime,
        rootPath: workbenchProject.rootPath,
        activeFilePath,
      }),
    [
      activeFilePath,
      activeOperatorSurface,
      adapterState,
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
          createdRepository={createdRepositoryNotice}
          creating={creatingRepository}
          onCreateRepository={createRepository}
          onDismissCreatedRepository={() => setCreatedRepositoryNotice(null)}
          onOpenRepository={openRepository}
          onToggleFavorite={toggleRepositoryFavorite}
        />
      ) : (
        <div className="chat-workspace-oss-shell__workbench">
          {!overlayVisible ? (
            <header className="chat-workspace-oss-shell__workbench-header">
              <button
                type="button"
                className="chat-workspace-oss-shell__back"
                onClick={returnToRepositoryGate}
              >
                {renderShellIcon(ArrowLeft, { size: 15, "aria-hidden": true })}
                <span>Workbench</span>
              </button>
              <div className="chat-workspace-oss-shell__workbench-title">
                <strong>{workbenchProject.name}</strong>
                <code>{workbenchProject.rootPath}</code>
              </div>
            </header>
          ) : null}

          <div
            className={clsx(
              "chat-workspace-oss-shell__workbench-surface",
              showOperatorChatPane &&
                "chat-workspace-oss-shell__workbench-surface--with-chat",
            )}
            style={
              showOperatorChatPane
                ? ({
                    "--workspace-operator-chat-width": `${operatorChatPaneWidthPx}px`,
                  } as CSSProperties)
                : undefined
            }
          >
            <div className="chat-workspace-oss-shell__surface-stage">
              {session && surface ? (
                <WorkspaceHost
                  key={surface.key}
                  className="chat-workspace-host"
                  adapter={surface.adapter}
                  root={surface.rootPath}
                  layoutMode={surface.layoutMode}
                  defaultPane={surface.defaultPane}
                  title={surface.title}
                  showHeader={surface.showHeader}
                  hideGlobalCommandCenter
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
              ) : null}

              {overlayVisible ? (
              <div className="chat-workspace-oss-shell__overlay">
                <div className="chat-workspace-oss-shell__fallback">
                  <div className="chat-workspace-oss-shell__fallback-bar">
                    <div className="chat-workspace-oss-shell__branch">
                      <span className="chat-workspace-oss-shell__status-dot" />
                      <strong>main</strong>
                      <span aria-hidden="true">⌄</span>
                    </div>
                    <div className="chat-workspace-oss-shell__adapter-pill">
                      Workspace session
                      <span aria-hidden="true">⌄</span>
                    </div>
                  </div>
                  <div className="chat-workspace-oss-shell__fallback-tabs">
                    <span>Code</span>
                    <strong>{workbenchProject.name}</strong>
                    <span className="is-active">Environment</span>
                  </div>

                  <div className="chat-workspace-oss-shell__fallback-grid">
                    <main className="chat-workspace-oss-shell__environment">
                      <div className="chat-workspace-oss-shell__environment-head">
                        <div className="chat-workspace-oss-shell__environment-title">
                          <span
                            className={clsx(
                              "chat-workspace-oss-shell__toggle",
                              !blockingError && "is-on",
                            )}
                            aria-hidden="true"
                          />
                          <h2>
                            {blockingError
                              ? "Environment needs runtime"
                              : "Environment starting"}
                          </h2>
                        </div>
                        <dl className="chat-workspace-oss-shell__environment-stats">
                          <div>
                            <dt>Auto-stop after</dt>
                            <dd>30m of inactivity</dd>
                          </div>
                          <div>
                            <dt>Created</dt>
                            <dd>5h ago</dd>
                          </div>
                          <div>
                            <dt>Last started</dt>
                            <dd>{session ? "now" : "pending"}</dd>
                          </div>
                          <div>
                            <dt>Resource usage</dt>
                            <dd className={blockingError ? "is-warn" : "is-ok"}>
                              {blockingError ? "Needs host" : "Healthy"}
                            </dd>
                          </div>
                        </dl>
                      </div>

                      <div className="chat-workspace-oss-shell__timeline">
                        {[
                          ["Resolved workspace root", workbenchProject.rootPath],
                          ["Loaded workspace refs", "Workspace state ready"],
                          ["Selected adapter", sessionDescriptor?.runtimeLabel ?? "Workspace session"],
                          [
                            blockingError
                              ? "Waiting for host adapter"
                              : "Starting governed session",
                            blockingError
                              ? blockingError.message
                              : "Runtime session launch in progress",
                          ],
                        ].map(([label, detail], index) => (
                          <div
                            className="chat-workspace-oss-shell__timeline-row"
                            key={label}
                          >
                            <span
                              className={clsx(
                                "chat-workspace-oss-shell__timeline-dot",
                                index < 3 && "is-complete",
                                index === 3 && blockingError && "is-warn",
                              )}
                            />
                            <div>
                              <strong>{label}</strong>
                              <span>{detail}</span>
                            </div>
                          </div>
                        ))}
                      </div>

                      {blockingError ? (
                        <div className="chat-workspace-oss-shell__error">
                          <strong>{blockingError.title}</strong>
                          <span>{blockingError.message}</span>
                          <details>
                            <summary>Advanced detail</summary>
                            <code>{blockingError.technicalDetail}</code>
                          </details>
                        </div>
                      ) : (
                        <div className="chat-workspace-oss-shell__runtime-pending">
                          <div
                            className="chat-workspace-oss-shell__spinner"
                            aria-hidden="true"
                          />
                          <span>
                            {sessionDescriptor?.startupDescription ??
                              "Starting the workspace runtime for this workspace."}
                          </span>
                        </div>
                      )}

                      {import.meta.env.DEV ? (
                        <details className="chat-workspace-oss-shell__diagnostics">
                          <summary>Diagnostics</summary>
                          <div className="chat-workspace-oss-shell__meta">
                            <span>Debug</span>
                            <code>
                              {`status=${status} session=${session ? "yes" : "no"} surface=${surface?.kind ?? "none"}`}
                            </code>
                          </div>
                          <div className="chat-workspace-oss-shell__meta">
                            <span>Phase</span>
                            <code>{bootPhase}</code>
                          </div>
                        </details>
                      ) : null}

                      <div className="chat-workspace-oss-shell__actions">
                        <button
                          type="button"
                          className="chat-workspace-oss-shell__button"
                          onClick={() => {
                            setSurfaceError(null);
                            restartWorkspace();
                          }}
                        >
                          {blockingError
                            ? "Retry workspace runtime"
                            : "Retry workspace surface"}
                        </button>
                      </div>
                    </main>

                    <aside className="chat-workspace-oss-shell__changes">
                      <div className="chat-workspace-oss-shell__changes-head">
                        <strong>Changes</strong>
                        <span aria-hidden="true">⌄</span>
                      </div>
                      <label className="chat-workspace-oss-shell__search">
                        <span>⌕</span>
                        <input readOnly value="" placeholder="Search files..." />
                      </label>
                      <div className="chat-workspace-oss-shell__change-list">
                        <div>
                          <span>.hypervisor/</span>
                          <em>2</em>
                        </div>
                        <div>
                          <code>session.json</code>
                          <strong>+20</strong>
                        </div>
                        <div>
                          <code>workspace.refs</code>
                          <strong>+5</strong>
                        </div>
                        <div>
                          <span>receipts/</span>
                          <em>1</em>
                        </div>
                      </div>
                      <div className="chat-workspace-oss-shell__bottom-panel">
                        <nav>
                          <strong>Ports & Services</strong>
                          <span>Tasks</span>
                          <span>Terminal</span>
                        </nav>
                        <div className="chat-workspace-oss-shell__ports">
                          <h3>Ports</h3>
                          <button type="button">+ Add port</button>
                        </div>
                        <p>No open ports</p>
                      </div>
                    </aside>
                  </div>
                </div>
              </div>
              ) : null}
            </div>

            {showOperatorChatPane ? (
              <aside
                className="chat-workspace-oss-shell__operator-chat-slot"
                aria-label="Hypervisor workspace chat"
              >
                {operatorChatPane}
              </aside>
            ) : null}
          </div>
        </div>
      )}
    </section>
  );
}
