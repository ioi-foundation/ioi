import clsx from "clsx";
import { workflowRuntimeUnavailableCopy } from "@ioi/hypervisor-workbench";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  WorkspaceHost,
  type WorkspacePersistedState,
  type WorkspaceSnapshot,
} from "@ioi/workspace-substrate";

import type { HypervisorClientRuntime } from "../../services/HypervisorClientRuntime";
import {
  loadWorkspaceShellState,
  persistWorkspaceShellState,
} from "../../services/workspaceShellState";
import type {
  WorkspaceSessionHost,
  WorkspaceSessionProjectDescriptor,
} from "../../services/workspaceSessionHost";
import { useWorkspaceSession } from "../../services/useWorkspaceSession";

interface WorkspaceShellProps {
  active: boolean;
  currentProject: WorkspaceSessionProjectDescriptor;
  projects?: WorkspaceSessionProjectDescriptor[];
  runtime: HypervisorClientRuntime;
  host: WorkspaceSessionHost;
  fullBleed?: boolean;
}

const DEFAULT_WORKBENCH_OPEN_PATH =
  "ioi/internal-docs/implementation/hypervisor-reference-grade-parity-master-guide.md";

function defaultWorkspaceShellState(): WorkspacePersistedState {
  return {
    activePane: "files",
    activeBottomPanel: "terminal",
    bottomPanelOpen: true,
    expandedPaths: {
      ioi: true,
      "ioi/internal-docs": true,
      "ioi/internal-docs/implementation": true,
    },
    documents: [{ kind: "file", path: DEFAULT_WORKBENCH_OPEN_PATH }],
    activeDocumentPath: DEFAULT_WORKBENCH_OPEN_PATH,
  };
}

function shellStateWithDefaultDocument(
  state: WorkspacePersistedState | null | undefined,
): WorkspacePersistedState {
  if (!state || state.documents.length === 0) {
    return defaultWorkspaceShellState();
  }
  return state;
}

export function WorkspaceShell({
  active,
  currentProject,
  runtime,
  host,
  fullBleed = false,
}: WorkspaceShellProps) {
  const {
    status,
    session,
    error,
    surfaceReady,
    surface,
    bootPhase,
    restartWorkspace,
  } = useWorkspaceSession({
    active,
    enabled: active,
    currentProject,
    runtime,
    host,
  });
  const sessionDescriptor = session ? host.describeSession(session) : null;
  const [persistedState, setPersistedState] = useState(() =>
    loadWorkspaceShellState(currentProject.rootPath),
  );
  const [surfaceError, setSurfaceError] = useState<string | null>(null);

  useEffect(() => {
    setPersistedState(loadWorkspaceShellState(currentProject.rootPath));
  }, [currentProject.rootPath]);

  useEffect(() => {
    setSurfaceError(null);
  }, [surface?.key]);

  const initialWorkspaceState = useMemo<WorkspacePersistedState | null>(
    () => shellStateWithDefaultDocument(persistedState?.shellState),
    [persistedState],
  );
  const initialWorkspaceSnapshot = persistedState?.snapshot ?? null;
  const persistedShellStateRef = useRef<WorkspacePersistedState | null>(
    initialWorkspaceState,
  );

  const surfaceKind = surface?.kind ?? null;
  const substratePreviewSurfaceVisible = surfaceKind === "substrate-preview";
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
    if (!import.meta.env.DEV || !active) {
      return;
    }
    console.info("[WorkspaceBoot] shell state", {
      rootPath: currentProject.rootPath,
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
    active,
    currentProject.rootPath,
  ]);

  useEffect(() => {
    persistedShellStateRef.current = persistedState?.shellState ?? initialWorkspaceState;
  }, [initialWorkspaceState, persistedState?.shellState]);

  const requestedOpenPath =
    persistedState?.lastActivePath ??
    initialWorkspaceState?.activeDocumentPath ??
    DEFAULT_WORKBENCH_OPEN_PATH;
  const requestedOpen = useMemo(
    () => ({ path: requestedOpenPath }),
    [requestedOpenPath],
  );

  const persistShellState = useCallback(
    (
      nextShellState: WorkspacePersistedState | null,
      nextActivePath?: string | null,
    ) => {
    setPersistedState((current) => {
      const nextState = {
        shellState: nextShellState
          ? shellStateWithDefaultDocument(nextShellState)
          : nextShellState,
        lastActivePath:
          nextActivePath === undefined
            ? (current?.lastActivePath ?? null)
            : nextActivePath,
        snapshot: current?.snapshot ?? null,
      };
      persistWorkspaceShellState(currentProject.rootPath, nextState);
      return nextState;
    });
    },
    [currentProject.rootPath],
  );

  const persistSnapshot = useCallback((nextSnapshot: WorkspaceSnapshot | null) => {
    setPersistedState((current) => {
      const nextState = {
        shellState: current?.shellState ?? defaultWorkspaceShellState(),
        lastActivePath: current?.lastActivePath ?? null,
        snapshot: nextSnapshot,
      };
      persistWorkspaceShellState(currentProject.rootPath, nextState);
      return nextState;
    });
  }, [currentProject.rootPath]);

  const persistActivePath = useCallback(
    (path: string | null) => {
      persistShellState(
        persistedShellStateRef.current ?? defaultWorkspaceShellState(),
        path,
      );
    },
    [persistShellState],
  );

  return (
    <section
      className={clsx(
        "hypervisor-workspace-shell",
        active && "is-active",
        fullBleed && "is-full-bleed",
      )}
      aria-label="Workspace"
      aria-hidden={!active}
    >
      <div className="hypervisor-workspace-shell__workbench">
        {!overlayVisible ? (
          <header className="hypervisor-workspace-shell__workbench-header">
            <div className="hypervisor-workspace-shell__workbench-title">
              <strong>{currentProject.name}</strong>
              <code>{currentProject.rootPath}</code>
            </div>
          </header>
        ) : null}

        <div className="hypervisor-workspace-shell__workbench-surface">
          <div className="hypervisor-workspace-shell__surface-stage">
            {session && surface ? (
              <WorkspaceHost
                key={surface.key}
                className="hypervisor-workspace-host"
                adapter={surface.adapter}
                root={surface.rootPath}
                layoutMode={surface.layoutMode}
                defaultPane={surface.defaultPane}
                title={surface.title}
                showHeader={surface.showHeader}
                showBottomPanel={surface.showBottomPanel}
                requestedOpen={requestedOpen}
                initialSnapshot={
                  surface.initialSnapshot ?? initialWorkspaceSnapshot
                }
                initialState={initialWorkspaceState}
                onStateChange={persistShellState}
                onSnapshotChange={persistSnapshot}
                onActivePathChange={persistActivePath}
              />
            ) : null}

            {overlayVisible ? (
              <div className="hypervisor-workspace-shell__overlay">
                <div className="hypervisor-workspace-shell__fallback">
                  <div className="hypervisor-workspace-shell__fallback-bar">
                    <div className="hypervisor-workspace-shell__branch">
                      <span className="hypervisor-workspace-shell__status-dot" />
                      <strong>main</strong>
                      <span aria-hidden="true">⌄</span>
                    </div>
                    <div className="hypervisor-workspace-shell__adapter-pill">
                      Workspace session
                      <span aria-hidden="true">⌄</span>
                    </div>
                  </div>
                  <div className="hypervisor-workspace-shell__fallback-tabs">
                    <span>Code</span>
                    <strong>{currentProject.name}</strong>
                    <span className="is-active">Environment</span>
                  </div>

                  <div className="hypervisor-workspace-shell__fallback-grid">
                    <main className="hypervisor-workspace-shell__environment">
                      <div className="hypervisor-workspace-shell__environment-head">
                        <div className="hypervisor-workspace-shell__environment-title">
                          <span
                            className={clsx(
                              "hypervisor-workspace-shell__toggle",
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
                        <dl className="hypervisor-workspace-shell__environment-stats">
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

                      <div className="hypervisor-workspace-shell__timeline">
                        {[
                          ["Resolved workspace root", currentProject.rootPath],
                          ["Loaded workspace refs", "Workspace state ready"],
                          [
                            "Selected adapter",
                            sessionDescriptor?.runtimeLabel ??
                              "Workspace session",
                          ],
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
                            className="hypervisor-workspace-shell__timeline-row"
                            key={label}
                          >
                            <span
                              className={clsx(
                                "hypervisor-workspace-shell__timeline-dot",
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
                        <div className="hypervisor-workspace-shell__error">
                          <strong>{blockingError.title}</strong>
                          <span>{blockingError.message}</span>
                          <details>
                            <summary>Advanced detail</summary>
                            <code>{blockingError.technicalDetail}</code>
                          </details>
                        </div>
                      ) : (
                        <div className="hypervisor-workspace-shell__runtime-pending">
                          <div
                            className="hypervisor-workspace-shell__spinner"
                            aria-hidden="true"
                          />
                          <span>
                            {sessionDescriptor?.startupDescription ??
                              "Starting the workspace runtime for this workspace."}
                          </span>
                        </div>
                      )}

                      {import.meta.env.DEV ? (
                        <details className="hypervisor-workspace-shell__diagnostics">
                          <summary>Diagnostics</summary>
                          <div className="hypervisor-workspace-shell__meta">
                            <span>Debug</span>
                            <code>
                              {`status=${status} session=${session ? "yes" : "no"} surface=${surface?.kind ?? "none"}`}
                            </code>
                          </div>
                          <div className="hypervisor-workspace-shell__meta">
                            <span>Phase</span>
                            <code>{bootPhase}</code>
                          </div>
                        </details>
                      ) : null}

                      <div className="hypervisor-workspace-shell__actions">
                        <button
                          type="button"
                          className="hypervisor-workspace-shell__button"
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

                    <aside className="hypervisor-workspace-shell__changes">
                      <div className="hypervisor-workspace-shell__changes-head">
                        <strong>Changes</strong>
                        <span aria-hidden="true">⌄</span>
                      </div>
                      <label className="hypervisor-workspace-shell__search">
                        <span>⌕</span>
                        <input
                          readOnly
                          value=""
                          placeholder="Search files..."
                        />
                      </label>
                      <div className="hypervisor-workspace-shell__change-list">
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
                      <div className="hypervisor-workspace-shell__bottom-panel">
                        <nav>
                          <strong>Ports & Services</strong>
                          <span>Tasks</span>
                          <span>Terminal</span>
                        </nav>
                        <div className="hypervisor-workspace-shell__ports">
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
        </div>
      </div>
    </section>
  );
}
