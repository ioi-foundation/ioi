import clsx from "clsx";
import { workflowRuntimeUnavailableCopy } from "@ioi/hypervisor-workbench";
import { useEffect, useMemo, useState } from "react";
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
    () => persistedState?.shellState ?? defaultWorkspaceShellState(),
    [persistedState],
  );
  const initialWorkspaceSnapshot = persistedState?.snapshot ?? null;

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

  const persistShellState = (
    nextShellState: WorkspacePersistedState | null,
    nextActivePath?: string | null,
  ) => {
    setPersistedState((current) => {
      const nextState = {
        shellState: nextShellState,
        lastActivePath:
          nextActivePath === undefined
            ? (current?.lastActivePath ?? null)
            : nextActivePath,
        snapshot: current?.snapshot ?? null,
      };
      persistWorkspaceShellState(currentProject.rootPath, nextState);
      return nextState;
    });
  };

  const persistSnapshot = (nextSnapshot: WorkspaceSnapshot | null) => {
    setPersistedState((current) => {
      const nextState = {
        shellState: current?.shellState ?? initialWorkspaceState,
        lastActivePath: current?.lastActivePath ?? null,
        snapshot: nextSnapshot,
      };
      persistWorkspaceShellState(currentProject.rootPath, nextState);
      return nextState;
    });
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
      <div className="chat-workspace-oss-shell__workbench">
        {!overlayVisible ? (
          <header className="chat-workspace-oss-shell__workbench-header">
            <div className="chat-workspace-oss-shell__workbench-title">
              <strong>{currentProject.name}</strong>
              <code>{currentProject.rootPath}</code>
            </div>
          </header>
        ) : null}

        <div className="chat-workspace-oss-shell__workbench-surface">
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
                showBottomPanel={surface.showBottomPanel}
                initialSnapshot={
                  surface.initialSnapshot ?? initialWorkspaceSnapshot
                }
                initialState={initialWorkspaceState}
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
                    <strong>{currentProject.name}</strong>
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
                        <input
                          readOnly
                          value=""
                          placeholder="Search files..."
                        />
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
        </div>
      </div>
    </section>
  );
}
