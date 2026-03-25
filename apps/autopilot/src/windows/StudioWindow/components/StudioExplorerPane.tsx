import { invoke } from "@tauri-apps/api/core";
import { useEffect, useMemo, useState } from "react";
import { StudioFileTypeIcon } from "./StudioFileTypeIcon";

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

function FolderFlapIcon({ isOpen }: { isOpen: boolean }) {
  return (
    <svg
      className={`studio-explorer-folder-icon ${isOpen ? "is-open" : ""}`}
      width="15"
      height="12"
      viewBox="0 0 29 22"
      fill="none"
      aria-hidden="true"
    >
      <path
        className="studio-explorer-folder-back"
        d="M2 4a1.5 1.5 0 011.5-1.5h5.2c.55 0 1.07.25 1.4.68L11.3 4.7c.2.25.5.3.7.3H21a2 2 0 012 2V18a2 2 0 01-2 2H4a2 2 0 01-2-2V4z"
      />
      <path
        className="studio-explorer-folder-front studio-explorer-folder-front--closed"
        d="M3.5 7.5h19a1.5 1.5 0 011.5 1.5v9a2 2 0 01-2 2H4a2 2 0 01-2-2V9a1.5 1.5 0 011.5-1.5z"
      />
      <path
        className="studio-explorer-folder-front studio-explorer-folder-front--open"
        d="M6.5 7.5h19a1.5 1.5 0 011.5 1.5L24 18a2 2 0 01-2 2H4a2 2 0 01-2-2L5 9a1.5 1.5 0 011.5-1.5z"
      />
    </svg>
  );
}

function countNodes(nodes: ProjectExplorerNode[]): number {
  return nodes.reduce(
    (total, node) => total + 1 + countNodes(node.children),
    0,
  );
}

function collectInitiallyExpandedPaths(
  activeFilePath: string | null,
): Record<string, boolean> {
  const next: Record<string, boolean> = {};
  if (!activeFilePath) {
    return next;
  }

  for (const path of ancestorPaths(activeFilePath)) {
    next[path] = true;
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

function lastPathSegment(path: string): string {
  const trimmed = path.replace(/\/+$/, "");
  const parts = trimmed.split("/").filter(Boolean);
  return parts[parts.length - 1] || path;
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
  const [rootExpanded, setRootExpanded] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setRootExpanded(true);

    void invoke<ProjectShellSnapshot>("project_shell_inspect", {
      root: currentProject.rootPath,
    })
      .then((result) => {
        if (!cancelled) {
          setSnapshot(result);
          setTreeNodes(result.tree);
          setExpandedPaths(collectInitiallyExpandedPaths(activeFilePath));
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
      setExpandedPaths(collectInitiallyExpandedPaths(activeFilePath));
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
  const rootPath = snapshot?.root_path || currentProject.rootPath;
  const rootLabel = lastPathSegment(rootPath);
  const repoStatusLabel = snapshot?.git.is_repo
    ? snapshot.git.dirty
      ? "Dirty"
      : "Clean"
    : "No repo";
  const branchLabel = snapshot?.git.is_repo
    ? snapshot.git.branch || "detached"
    : "git unavailable";

  const hasExpandedChildDirectory = (nodes: ProjectExplorerNode[]): boolean =>
    nodes.some(
      (node) => node.kind === "directory" && !!expandedPaths[node.path],
    );

  const renderTree = (nodes: ProjectExplorerNode[]) =>
    nodes.map((node) => {
      const isDirectory = node.kind === "directory";
      const isExpanded = isDirectory && expandedPaths[node.path];
      const isLoading = !!loadingDirectories[node.path];
      const isActiveFile = !isDirectory && activeFilePath === node.path;
      const childGuideTone = hasExpandedChildDirectory(node.children)
        ? "is-ancestor"
        : "is-youngest";

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
            onClick={() =>
              isDirectory ? toggleDirectory(node) : onOpenFile(node.path)
            }
          >
            {isDirectory ? (
              <FolderFlapIcon isOpen={!!isExpanded} />
            ) : (
              <StudioFileTypeIcon name={node.name} context="explorer" />
            )}
            <span className="studio-explorer-tree-name">{node.name}</span>
          </button>

          {isDirectory && isExpanded ? (
            <div
              className={`studio-explorer-tree-children ${childGuideTone}`}
            >
              {isLoading && node.children.length === 0 ? (
                <p className="studio-explorer-feedback studio-explorer-feedback--nested">
                  Loading...
                </p>
              ) : (
                renderTree(node.children)
              )}
            </div>
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
        <section className="studio-explorer-meta">
          <div className="studio-explorer-meta-row">
            <span className="studio-explorer-chip">{branchLabel}</span>
            <span
              className={`studio-explorer-chip ${
                snapshot?.git.is_repo
                  ? snapshot.git.dirty
                    ? "is-dirty"
                    : "is-clean"
                  : "is-muted"
              }`}
            >
              {repoStatusLabel}
            </span>
            <span className="studio-explorer-chip is-muted">
              {totalTreeNodes} items
            </span>
          </div>
          <p className="studio-explorer-root-path" title={rootPath}>
            {rootPath}
          </p>
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

        <section className="studio-explorer-tree-shell">
          <button
            type="button"
            className={`studio-explorer-root-row ${rootExpanded ? "is-expanded" : ""}`}
            onClick={() => setRootExpanded((current) => !current)}
            aria-expanded={rootExpanded}
          >
            <FolderFlapIcon isOpen={rootExpanded} />
            <span className="studio-explorer-tree-name">{rootLabel}</span>
          </button>

          {loading ? (
            <p className="studio-explorer-feedback">Loading project tree...</p>
          ) : null}
          {error ? <p className="studio-explorer-feedback">{error}</p> : null}
          {!loading && !error && snapshot && rootExpanded ? (
            <div
              className={`studio-explorer-tree ${
                hasExpandedChildDirectory(treeNodes)
                  ? "is-ancestor"
                  : "is-youngest"
              }`}
            >
              {renderTree(treeNodes)}
            </div>
          ) : null}
        </section>
      </div>
    </aside>
  );
}
