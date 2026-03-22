import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";

interface ProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

interface ProjectGitStatus {
  is_repo: boolean;
  branch: string | null;
  dirty: boolean;
  last_commit: string | null;
}

interface ProjectExplorerNode {
  name: string;
  path: string;
  kind: string;
  has_children: boolean;
  children: ProjectExplorerNode[];
}

interface ProjectArtifactCandidate {
  title: string;
  path: string;
  artifact_type: string;
}

interface ProjectShellSnapshot {
  root_path: string;
  git: ProjectGitStatus;
  tree: ProjectExplorerNode[];
  artifacts: ProjectArtifactCandidate[];
}

interface StudioExplorerPaneProps {
  currentProject: ProjectScope;
  activeFilePath: string | null;
  onOpenFile: (path: string) => void;
}

function MoreActionsIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <circle cx="5" cy="12" r="1.5" fill="currentColor" stroke="none" />
      <circle cx="12" cy="12" r="1.5" fill="currentColor" stroke="none" />
      <circle cx="19" cy="12" r="1.5" fill="currentColor" stroke="none" />
    </svg>
  );
}

function countNodes(nodes: ProjectExplorerNode[]): number {
  return nodes.reduce(
    (total, node) => total + 1 + countNodes(node.children),
    0,
  );
}

function collectInitiallyExpandedPaths(nodes: ProjectExplorerNode[]): Record<string, boolean> {
  const next: Record<string, boolean> = {};
  for (const node of nodes) {
    if (node.kind === "directory") {
      next[node.path] = true;
    }
  }
  return next;
}

function ancestorPaths(path: string): string[] {
  const parts = path.split("/").filter(Boolean);
  const ancestors: string[] = [];
  for (let index = 0; index < parts.length - 1; index += 1) {
    ancestors.push(parts.slice(0, index + 1).join("/"));
  }
  return ancestors;
}

function replaceNodeChildren(
  nodes: ProjectExplorerNode[],
  targetPath: string,
  nextChildren: ProjectExplorerNode[],
): ProjectExplorerNode[] {
  return nodes.map((node) => {
    if (node.path === targetPath) {
      return {
        ...node,
        has_children: nextChildren.length > 0,
        children: nextChildren,
      };
    }

    if (node.children.length === 0) {
      return node;
    }

    return {
      ...node,
      children: replaceNodeChildren(node.children, targetPath, nextChildren),
    };
  });
}

export function StudioExplorerPane({
  currentProject,
  activeFilePath,
  onOpenFile,
}: StudioExplorerPaneProps) {
  const [snapshot, setSnapshot] = useState<ProjectShellSnapshot | null>(null);
  const [treeNodes, setTreeNodes] = useState<ProjectExplorerNode[]>([]);
  const [expandedPaths, setExpandedPaths] = useState<Record<string, boolean>>({});
  const [loadingDirectories, setLoadingDirectories] = useState<Record<string, boolean>>(
    {},
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [initBusy, setInitBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    void invoke<ProjectShellSnapshot>("project_shell_inspect", {
      root: currentProject.rootPath,
    })
      .then((result) => {
        if (!cancelled) {
          setSnapshot(result);
          setTreeNodes(result.tree);
          setExpandedPaths(collectInitiallyExpandedPaths(result.tree));
        }
      })
      .catch((nextError) => {
        if (!cancelled) {
          setError(String(nextError));
          setSnapshot(null);
          setTreeNodes([]);
          setExpandedPaths({});
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [currentProject.rootPath]);

  useEffect(() => {
    if (!activeFilePath) return;
    const ancestors = ancestorPaths(activeFilePath);
    if (ancestors.length === 0) return;
    setExpandedPaths((current) => {
      const next = { ...current };
      for (const path of ancestors) {
        next[path] = true;
      }
      return next;
    });
  }, [activeFilePath]);

  const initializeRepository = async () => {
    setInitBusy(true);
    setError(null);
    try {
      const result = await invoke<ProjectShellSnapshot>(
        "project_initialize_repository",
        {
          root: currentProject.rootPath,
        },
      );
      setSnapshot(result);
      setTreeNodes(result.tree);
      setExpandedPaths(collectInitiallyExpandedPaths(result.tree));
    } catch (nextError) {
      setError(String(nextError));
    } finally {
      setInitBusy(false);
    }
  };

  const loadDirectory = async (directoryPath: string) => {
    setLoadingDirectories((current) => ({
      ...current,
      [directoryPath]: true,
    }));

    try {
      const children = await invoke<ProjectExplorerNode[]>(
        "project_shell_list_directory",
        {
          root: currentProject.rootPath,
          directory: directoryPath,
        },
      );
      setTreeNodes((current) =>
        replaceNodeChildren(current, directoryPath, children),
      );
    } catch (nextError) {
      setError(String(nextError));
    } finally {
      setLoadingDirectories((current) => {
        const next = { ...current };
        delete next[directoryPath];
        return next;
      });
    }
  };

  const toggleDirectory = (node: ProjectExplorerNode) => {
    const nextExpanded = !expandedPaths[node.path];
    setExpandedPaths((current) => ({
      ...current,
      [node.path]: nextExpanded,
    }));

    if (
      nextExpanded &&
      node.has_children &&
      node.children.length === 0 &&
      !loadingDirectories[node.path]
    ) {
      void loadDirectory(node.path);
    }
  };

  const totalTreeNodes = useMemo(() => countNodes(treeNodes), [treeNodes]);
  const visibleArtifacts = snapshot?.artifacts.slice(0, 4) ?? [];

  const renderTree = (nodes: ProjectExplorerNode[], depth = 0) =>
    nodes.map((node) => {
      const isDirectory = node.kind === "directory";
      const isExpanded = isDirectory && expandedPaths[node.path];
      const isLoading = !!loadingDirectories[node.path];
      const isActiveFile = !isDirectory && activeFilePath === node.path;

      return (
        <div
          key={`${node.kind}:${node.path}`}
          className="studio-explorer-tree-group"
        >
          <button
            type="button"
            className={`studio-explorer-tree-row ${
              isDirectory ? "is-directory" : "is-file"
            } ${isExpanded ? "is-expanded" : ""} ${
              isActiveFile ? "is-active" : ""
            }`}
            style={{ paddingLeft: `${10 + depth * 14}px` }}
            onClick={() =>
              isDirectory ? toggleDirectory(node) : onOpenFile(node.path)
            }
          >
            <span
              className={`studio-explorer-tree-caret ${
                isDirectory && node.has_children ? "is-visible" : ""
              } ${isExpanded ? "is-expanded" : ""}`}
              aria-hidden="true"
            >
              ▸
            </span>
            <span
              className={`studio-explorer-tree-kind ${
                isDirectory ? "is-directory" : "is-file"
              }`}
              aria-hidden="true"
            />
            <span className="studio-explorer-tree-name">{node.name}</span>
          </button>

          {isDirectory && isExpanded ? (
            isLoading && node.children.length === 0 ? (
              <p
                className="studio-explorer-feedback studio-explorer-feedback--nested"
                style={{ paddingLeft: `${30 + depth * 14}px` }}
              >
                Loading...
              </p>
            ) : (
              renderTree(node.children, depth + 1)
            )
          ) : null}
        </div>
      );
    });

  return (
    <aside className="studio-explorer-pane" aria-label="Project explorer">
      <div className="studio-explorer-pane-controls">
        <span className="studio-explorer-pane-title">Explorer</span>
        <button
          type="button"
          className="studio-chat-pane-control studio-explorer-pane-control"
          aria-label="Views and more actions"
          title="Views and More Actions"
        >
          <MoreActionsIcon />
        </button>
      </div>

      <div className="studio-explorer-body">
        <section className="studio-explorer-card">
          <div className="studio-explorer-card-head">
            <strong>Workspace</strong>
            <span>Root</span>
          </div>
          <p>{snapshot?.root_path || currentProject.rootPath}</p>
        </section>

        <section className="studio-explorer-card">
          <div className="studio-explorer-card-head">
            <strong>Repository</strong>
            <span>
              {snapshot?.git.is_repo
                ? snapshot.git.dirty
                  ? "Dirty"
                  : "Clean"
                : "Not initialized"}
            </span>
          </div>
          {snapshot?.git.is_repo ? (
            <p>
              Branch {snapshot.git.branch || "detached"} ·{" "}
              {snapshot.git.last_commit || "No commits yet"}
            </p>
          ) : (
            <p>
              Initialize a repository so edits, diffs, and worker runs stay
              scoped to a known project boundary.
            </p>
          )}
          {!snapshot?.git.is_repo ? (
            <button
              type="button"
              className="studio-explorer-action"
              onClick={initializeRepository}
              disabled={initBusy}
            >
              {initBusy ? "Initializing..." : "Initialize repository"}
            </button>
          ) : null}
        </section>

        <section className="studio-explorer-card studio-explorer-card--tree">
          <div className="studio-explorer-card-head">
            <strong>Files</strong>
            <span>{totalTreeNodes}</span>
          </div>
          {loading ? (
            <p className="studio-explorer-feedback">Loading project tree...</p>
          ) : null}
          {error ? <p className="studio-explorer-feedback">{error}</p> : null}
          {!loading && !error && snapshot ? (
            <div className="studio-explorer-tree">{renderTree(treeNodes)}</div>
          ) : null}
        </section>

        <section className="studio-explorer-card">
          <div className="studio-explorer-card-head">
            <strong>Artifacts</strong>
            <span>{snapshot?.artifacts.length || 0}</span>
          </div>
          {loading ? (
            <p className="studio-explorer-feedback">Loading artifacts...</p>
          ) : null}
          {error ? <p className="studio-explorer-feedback">{error}</p> : null}
          {!loading && !error && snapshot ? (
            visibleArtifacts.length > 0 ? (
              <div className="studio-explorer-artifact-list">
                {visibleArtifacts.map((artifact) => (
                  <button
                    key={`${artifact.artifact_type}:${artifact.path}`}
                    type="button"
                    className="studio-explorer-artifact"
                    onClick={() => onOpenFile(artifact.path)}
                  >
                    <div className="studio-explorer-artifact-head">
                      <strong>{artifact.title}</strong>
                      <span>{artifact.artifact_type}</span>
                    </div>
                    <p>{artifact.path}</p>
                  </button>
                ))}
              </div>
            ) : (
              <p className="studio-explorer-feedback">
                Run workflows or export reports and they will appear here.
              </p>
            )
          ) : null}
        </section>
      </div>
    </aside>
  );
}
