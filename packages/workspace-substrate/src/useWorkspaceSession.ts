import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  WorkspaceAdapter,
  WorkspaceActivityEntry,
  WorkspaceBottomPanel,
  WorkspaceDiffDocument,
  WorkspaceFileDocument,
  WorkspaceNode,
  WorkspaceOpenRequest,
  WorkspacePane,
  WorkspacePortEntry,
  WorkspaceProblemEntry,
  WorkspaceSearchResult,
  WorkspaceSnapshot,
  WorkspaceSourceControlState,
  WorkspaceTerminalController,
} from "./types";

export interface WorkspaceFileTab extends WorkspaceFileDocument {
  id: string;
  kind: "file";
  loading: boolean;
  saving: boolean;
  error: string | null;
  savedContent: string;
}

export interface WorkspaceDiffTab {
  id: string;
  kind: "diff";
  path: string;
  title: string;
  diff: WorkspaceDiffDocument;
}

export type WorkspaceDocumentTab = WorkspaceFileTab | WorkspaceDiffTab;

interface UseWorkspaceSessionOptions {
  adapter: WorkspaceAdapter;
  root: string;
  terminalController: WorkspaceTerminalController;
  initialPane?: WorkspacePane;
  initialBottomPanel?: WorkspaceBottomPanel;
  externalOpenRequest?: WorkspaceOpenRequest | null;
  onActivePathChange?: (path: string | null) => void;
  onActivityChange?: (activity: WorkspaceActivityEntry[]) => void;
}

function fileTabId(path: string): string {
  return `file:${path}`;
}

function diffTabId(path: string, staged: boolean): string {
  return `diff:${staged ? "staged" : "working"}:${path}`;
}

function isFileTab(tab: WorkspaceDocumentTab): tab is WorkspaceFileTab {
  return tab.kind === "file";
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
  nodes: WorkspaceNode[],
  targetPath: string,
  children: WorkspaceNode[],
): WorkspaceNode[] {
  return nodes.map((node) => {
    if (node.path === targetPath) {
      return {
        ...node,
        children,
        hasChildren: children.length > 0,
      };
    }

    if (node.children.length === 0) {
      return node;
    }

    return {
      ...node,
      children: replaceNodeChildren(node.children, targetPath, children),
    };
  });
}

function relativeDirectoryForPath(path: string | null): string {
  if (!path || path === ".") {
    return "";
  }
  const parts = path.split("/").filter(Boolean);
  parts.pop();
  return parts.join("/");
}

function closeDeletedTabs(
  tabs: WorkspaceDocumentTab[],
  deletedPath: string,
): WorkspaceDocumentTab[] {
  return tabs.filter((tab) => {
    if (tab.path === deletedPath) {
      return false;
    }
    return !tab.path.startsWith(`${deletedPath}/`);
  });
}

function createActivityEntry(
  sequence: number,
  kind: WorkspaceActivityEntry["kind"],
  source: string,
  title: string,
  detail: string | null = null,
  path?: string,
): WorkspaceActivityEntry {
  return {
    id: `activity:${sequence}`,
    kind,
    source,
    title,
    detail,
    timestampMs: Date.now(),
    path,
  };
}

export function useWorkspaceSession({
  adapter,
  root,
  terminalController,
  initialPane = "files",
  initialBottomPanel = "output",
  externalOpenRequest = null,
  onActivePathChange,
  onActivityChange,
}: UseWorkspaceSessionOptions) {
  const [activePane, setActivePane] = useState<WorkspacePane>(initialPane);
  const [snapshot, setSnapshot] = useState<WorkspaceSnapshot | null>(null);
  const [treeNodes, setTreeNodes] = useState<WorkspaceNode[]>([]);
  const [expandedPaths, setExpandedPaths] = useState<Record<string, boolean>>({});
  const [loadingDirectories, setLoadingDirectories] = useState<Record<string, boolean>>(
    {},
  );
  const [workspaceLoading, setWorkspaceLoading] = useState(false);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);
  const [documents, setDocuments] = useState<WorkspaceDocumentTab[]>([]);
  const [activeDocumentId, setActiveDocumentId] = useState<string | null>(null);
  const [revealRequest, setRevealRequest] = useState<WorkspaceOpenRequest | null>(null);
  const [searchDraft, setSearchDraft] = useState("");
  const [searchLoading, setSearchLoading] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [searchResult, setSearchResult] = useState<WorkspaceSearchResult | null>(null);
  const [sourceControlState, setSourceControlState] = useState<WorkspaceSourceControlState | null>(
    null,
  );
  const [sourceControlLoading, setSourceControlLoading] = useState(false);
  const [sourceControlError, setSourceControlError] = useState<string | null>(null);
  const [activeBottomPanel, setActiveBottomPanel] =
    useState<WorkspaceBottomPanel>(initialBottomPanel);
  const [bottomPanelOpen, setBottomPanelOpen] = useState(true);
  const [workspaceActivity, setWorkspaceActivity] = useState<WorkspaceActivityEntry[]>([]);

  const activeDocument = useMemo(
    () => documents.find((tab) => tab.id === activeDocumentId) ?? null,
    [activeDocumentId, documents],
  );
  const documentsRef = useRef<WorkspaceDocumentTab[]>([]);
  const activeFilePathRef = useRef<string | null>(null);
  const activitySequenceRef = useRef(0);

  const appendActivity = useCallback(
    (
      kind: WorkspaceActivityEntry["kind"],
      source: string,
      title: string,
      detail: string | null = null,
      path?: string,
    ) => {
      activitySequenceRef.current += 1;
      const entry = createActivityEntry(
        activitySequenceRef.current,
        kind,
        source,
        title,
        detail,
        path,
      );
      setWorkspaceActivity((current) => [entry, ...current].slice(0, 80));
    },
    [],
  );

  useEffect(() => {
    documentsRef.current = documents;
  }, [documents]);

  const activeFilePath =
    activeDocument?.kind === "file"
      ? activeDocument.path
      : activeDocument?.path ?? null;

  useEffect(() => {
    activeFilePathRef.current = activeFilePath;
  }, [activeFilePath]);

  const activity = useMemo<WorkspaceActivityEntry[]>(() => {
    return [...terminalController.activityEntries, ...workspaceActivity]
      .sort((left, right) => right.timestampMs - left.timestampMs)
      .slice(0, 120);
  }, [terminalController.activityEntries, workspaceActivity]);

  const outputEntries = useMemo<WorkspaceActivityEntry[]>(() => {
    return [...terminalController.outputEntries, ...workspaceActivity]
      .sort((left, right) => right.timestampMs - left.timestampMs)
      .slice(0, 160);
  }, [terminalController.outputEntries, workspaceActivity]);

  const loadWorkspace = useCallback(async () => {
    setWorkspaceLoading(true);
    setWorkspaceError(null);
    try {
      const nextSnapshot = await adapter.inspectWorkspace(root);
      setSnapshot(nextSnapshot);
      setTreeNodes(nextSnapshot.tree);
      setExpandedPaths((current) => {
        const focusedPath = activeFilePathRef.current;
        if (!focusedPath) {
          return current;
        }
        const next = { ...current };
        for (const path of ancestorPaths(focusedPath)) {
          next[path] = true;
        }
        return next;
      });
    } catch (error) {
      const message = String(error);
      setWorkspaceError(message);
      setSnapshot(null);
      setTreeNodes([]);
      setBottomPanelOpen(true);
      setActiveBottomPanel("problems");
      appendActivity("error", "workspace", "Workspace refresh failed", message);
    } finally {
      setWorkspaceLoading(false);
    }
  }, [adapter, appendActivity, root]);

  const refreshSourceControl = useCallback(async () => {
    setSourceControlLoading(true);
    setSourceControlError(null);
    try {
      const state = await adapter.getSourceControlState(root);
      setSourceControlState(state);
    } catch (error) {
      const message = String(error);
      setSourceControlError(message);
      setSourceControlState(null);
      setBottomPanelOpen(true);
      setActiveBottomPanel("problems");
      appendActivity("error", "source-control", "Source control refresh failed", message);
    } finally {
      setSourceControlLoading(false);
    }
  }, [adapter, appendActivity, root]);

  useEffect(() => {
    setDocuments([]);
    setActiveDocumentId(null);
    setRevealRequest(null);
    setSearchDraft("");
    setSearchResult(null);
    setSearchError(null);
    setExpandedPaths({});
    setLoadingDirectories({});
    setActiveBottomPanel(initialBottomPanel);
    setBottomPanelOpen(true);
    activitySequenceRef.current = 0;
    setWorkspaceActivity([]);
    appendActivity("info", "workspace", "Workspace session ready", root);
    void loadWorkspace();
    void refreshSourceControl();
  }, [appendActivity, initialBottomPanel, loadWorkspace, refreshSourceControl, root]);

  useEffect(() => {
    if (!onActivePathChange) {
      return;
    }
    onActivePathChange(activeFilePath);
  }, [activeFilePath, onActivePathChange]);

  useEffect(() => {
    if (!onActivityChange) {
      return;
    }
    onActivityChange(activity);
  }, [activity, onActivityChange]);

  useEffect(() => {
    if (activePane !== "source-control") {
      return;
    }
    void refreshSourceControl();
  }, [activePane, refreshSourceControl]);

  const openFile = useCallback(
    async (request: WorkspaceOpenRequest) => {
      const existingId = fileTabId(request.path);
      setExpandedPaths((current) => {
        const next = { ...current };
        for (const path of ancestorPaths(request.path)) {
          next[path] = true;
        }
        return next;
      });
      setActivePane("files");
      setRevealRequest(request);

      const existing = documentsRef.current.find((tab) => tab.id === existingId);
      if (existing) {
        setActiveDocumentId(existingId);
        return;
      }

      setDocuments((current) => [
        ...current,
        {
          id: existingId,
          kind: "file",
          name: request.path.split("/").pop() || request.path,
          path: request.path,
          absolutePath: "",
          languageHint: null,
          content: "",
          savedContent: "",
          sizeBytes: 0,
          modifiedAtMs: null,
          isBinary: false,
          isTooLarge: false,
          readOnly: false,
          loading: true,
          saving: false,
          error: null,
        },
      ]);
      setActiveDocumentId(existingId);

      try {
        const document = await adapter.readFile(root, request.path);
        setDocuments((current) =>
          current.map((tab) =>
            tab.id === existingId && tab.kind === "file"
              ? {
                  ...document,
                  id: existingId,
                  kind: "file",
                  savedContent: document.content,
                  loading: false,
                  saving: false,
                  error: null,
                }
              : tab,
          ),
        );
        appendActivity("info", "editor", `Opened ${document.name}`, request.path, request.path);
      } catch (error) {
        const message = String(error);
        setDocuments((current) =>
          current.map((tab) =>
            tab.id === existingId && tab.kind === "file"
              ? {
                  ...tab,
                  loading: false,
                  saving: false,
                  error: message,
                }
              : tab,
          ),
        );
        setBottomPanelOpen(true);
        setActiveBottomPanel("problems");
        appendActivity("error", "editor", `Failed to open ${request.path}`, message, request.path);
      }
    },
    [adapter, appendActivity, root],
  );

  useEffect(() => {
    if (!externalOpenRequest?.path) {
      return;
    }
    void openFile(externalOpenRequest);
  }, [externalOpenRequest, openFile]);

  const consumeRevealRequest = useCallback(() => {
    setRevealRequest(null);
  }, []);

  const toggleDirectory = useCallback(
    async (node: WorkspaceNode) => {
      if (node.kind !== "directory") {
        return;
      }

      const nextExpanded = !expandedPaths[node.path];
      setExpandedPaths((current) => ({
        ...current,
        [node.path]: nextExpanded,
      }));

      if (
        nextExpanded &&
        node.hasChildren &&
        node.children.length === 0 &&
        !loadingDirectories[node.path]
      ) {
        setLoadingDirectories((current) => ({
          ...current,
          [node.path]: true,
        }));
        try {
          const children = await adapter.listDirectory(root, node.path);
          setTreeNodes((current) => replaceNodeChildren(current, node.path, children));
        } catch (error) {
          setWorkspaceError(String(error));
        } finally {
          setLoadingDirectories((current) => {
            const next = { ...current };
            delete next[node.path];
            return next;
          });
        }
      }
    },
    [adapter, expandedPaths, loadingDirectories, root],
  );

  const updateFileContent = useCallback((path: string, content: string) => {
    const targetId = fileTabId(path);
    setDocuments((current) =>
      current.map((tab) =>
        tab.id === targetId && tab.kind === "file"
          ? {
              ...tab,
              content,
            }
          : tab,
      ),
    );
  }, []);

  const saveFile = useCallback(
    async (path: string) => {
      const targetId = fileTabId(path);
      const tab = documents.find(
        (candidate): candidate is WorkspaceFileTab =>
          candidate.id === targetId && candidate.kind === "file",
      );

      if (
        !tab ||
        tab.loading ||
        tab.saving ||
        tab.readOnly ||
        tab.content === tab.savedContent
      ) {
        return;
      }

      setDocuments((current) =>
        current.map((candidate) =>
          candidate.id === targetId && candidate.kind === "file"
            ? {
                ...candidate,
                saving: true,
                error: null,
              }
            : candidate,
        ),
      );

      try {
        const document = await adapter.writeFile(root, path, tab.content);
        setDocuments((current) =>
          current.map((candidate) =>
            candidate.id === targetId && candidate.kind === "file"
              ? {
                  ...document,
                  id: targetId,
                  kind: "file",
                  savedContent: document.content,
                  loading: false,
                  saving: false,
                  error: null,
                }
              : candidate,
          ),
        );
        appendActivity("success", "editor", `Saved ${document.name}`, path, path);
        void refreshSourceControl();
        void loadWorkspace();
      } catch (error) {
        const message = String(error);
        setDocuments((current) =>
          current.map((candidate) =>
            candidate.id === targetId && candidate.kind === "file"
              ? {
                  ...candidate,
                  saving: false,
                  error: message,
                }
              : candidate,
          ),
        );
        setBottomPanelOpen(true);
        setActiveBottomPanel("problems");
        appendActivity("error", "editor", `Save failed for ${path}`, message, path);
      }
    },
    [adapter, appendActivity, documents, loadWorkspace, refreshSourceControl, root],
  );

  const closeDocument = useCallback(
    (id: string) => {
      const target = documents.find((tab) => tab.id === id);
      if (
        target &&
        isFileTab(target) &&
        target.content !== target.savedContent &&
        !window.confirm(`Close ${target.name} without saving changes?`)
      ) {
        return;
      }

      const currentIndex = documents.findIndex((tab) => tab.id === id);
      const remaining = documents.filter((tab) => tab.id !== id);
      setDocuments(remaining);

      if (activeDocumentId === id) {
        const next =
          remaining[currentIndex] ??
          remaining[currentIndex - 1] ??
          remaining[0] ??
          null;
        setActiveDocumentId(next?.id ?? null);
      }
    },
    [activeDocumentId, documents],
  );

  const runSearch = useCallback(async () => {
    const query = searchDraft.trim();
    if (!query) {
      setSearchResult(null);
      setSearchError(null);
      return;
    }

    setActivePane("search");
    setSearchLoading(true);
    setSearchError(null);
    try {
      const result = await adapter.searchText(root, query);
      setSearchResult(result);
      setBottomPanelOpen(true);
      setActiveBottomPanel("output");
      appendActivity(
        "success",
        "search",
        `Found ${result.totalMatches} matches for "${query}"`,
        `${result.files.length} files matched.`,
      );
    } catch (error) {
      const message = String(error);
      setSearchError(message);
      setSearchResult(null);
      setBottomPanelOpen(true);
      setActiveBottomPanel("problems");
      appendActivity("error", "search", `Search failed for "${query}"`, message);
    } finally {
      setSearchLoading(false);
    }
  }, [adapter, appendActivity, root, searchDraft]);

  const openDiff = useCallback(
    async (path: string, staged: boolean) => {
      const id = diffTabId(path, staged);
      try {
        const diff = await adapter.getDiff(root, path, staged);
        setDocuments((current) => {
          const existing = current.find((tab) => tab.id === id);
          if (existing) {
            return current.map((tab) =>
              tab.id === id && tab.kind === "diff"
                ? {
                    ...tab,
                    path,
                    title: diff.title,
                    diff,
                  }
                : tab,
            );
          }

          return [
            ...current,
            {
              id,
              kind: "diff",
              path,
              title: diff.title,
              diff,
            },
          ];
        });
        setActiveDocumentId(id);
        setActivePane("source-control");
        setBottomPanelOpen(true);
        setActiveBottomPanel("output");
        appendActivity(
          "info",
          "source-control",
          `${staged ? "Opened staged" : "Opened working"} diff`,
          path,
          path,
        );
      } catch (error) {
        const message = String(error);
        setSourceControlError(message);
        setBottomPanelOpen(true);
        setActiveBottomPanel("problems");
        appendActivity("error", "source-control", `Failed to diff ${path}`, message, path);
      }
    },
    [adapter, appendActivity, documents, root],
  );

  const mutateSourceControl = useCallback(
    async (
      action: (workspaceRoot: string, paths: string[]) => Promise<WorkspaceSourceControlState>,
      path: string,
      actionLabel: string,
    ) => {
      try {
        const nextState = await action(root, [path]);
        setSourceControlState(nextState);
        void loadWorkspace();
        if (activeDocument?.kind === "diff" && activeDocument.path === path) {
          void openDiff(path, activeDocument.id.startsWith("diff:staged:"));
        }
        setBottomPanelOpen(true);
        setActiveBottomPanel("output");
        appendActivity("success", "source-control", `${actionLabel} ${path}`, null, path);
      } catch (error) {
        const message = String(error);
        setSourceControlError(message);
        setBottomPanelOpen(true);
        setActiveBottomPanel("problems");
        appendActivity(
          "error",
          "source-control",
          `${actionLabel} failed for ${path}`,
          message,
          path,
        );
      }
    },
    [activeDocument, appendActivity, loadWorkspace, openDiff, root],
  );

  const createFile = useCallback(async () => {
    const defaultPath = relativeDirectoryForPath(activeFilePath);
    const nextPath = window.prompt(
      "Create file at relative path",
      defaultPath ? `${defaultPath}/new-file.ts` : "new-file.ts",
    );
    if (!nextPath?.trim()) {
      return;
    }

    try {
      const document = await adapter.createFile(root, nextPath.trim());
      await loadWorkspace();
      await refreshSourceControl();
      await openFile({ path: document.path });
      setBottomPanelOpen(true);
      setActiveBottomPanel("output");
      appendActivity("success", "workspace", `Created ${document.path}`, null, document.path);
    } catch (error) {
      const message = String(error);
      setWorkspaceError(message);
      setBottomPanelOpen(true);
      setActiveBottomPanel("problems");
      appendActivity("error", "workspace", `Create file failed for ${nextPath.trim()}`, message);
    }
  }, [
    activeFilePath,
    adapter,
    appendActivity,
    loadWorkspace,
    openFile,
    refreshSourceControl,
    root,
  ]);

  const createDirectory = useCallback(async () => {
    const defaultPath = relativeDirectoryForPath(activeFilePath);
    const nextPath = window.prompt(
      "Create folder at relative path",
      defaultPath ? `${defaultPath}/new-folder` : "new-folder",
    );
    if (!nextPath?.trim()) {
      return;
    }

    try {
      await adapter.createDirectory(root, nextPath.trim());
      await loadWorkspace();
      await refreshSourceControl();
      setBottomPanelOpen(true);
      setActiveBottomPanel("output");
      appendActivity("success", "workspace", `Created ${nextPath.trim()}`, null, nextPath.trim());
    } catch (error) {
      const message = String(error);
      setWorkspaceError(message);
      setBottomPanelOpen(true);
      setActiveBottomPanel("problems");
      appendActivity(
        "error",
        "workspace",
        `Create folder failed for ${nextPath.trim()}`,
        message,
      );
    }
  }, [
    activeFilePath,
    adapter,
    appendActivity,
    loadWorkspace,
    refreshSourceControl,
    root,
  ]);

  const renamePath = useCallback(
    async (path: string) => {
      const nextPath = window.prompt("Rename path", path);
      if (!nextPath?.trim() || nextPath.trim() === path) {
        return;
      }

      try {
        const result = await adapter.renamePath(root, path, nextPath.trim());
        let nextActiveDocumentId: string | null = activeDocumentId;
        setDocuments((current) =>
          current.map((tab) => {
            if (tab.path === path || tab.path.startsWith(`${path}/`)) {
              const remappedPath = tab.path.replace(path, result.path);
              if (tab.id === activeDocumentId) {
                nextActiveDocumentId =
                  tab.kind === "file"
                    ? fileTabId(remappedPath)
                    : tab.id.replace(path, result.path);
              }
              if (tab.kind === "file") {
                return {
                  ...tab,
                  id: fileTabId(remappedPath),
                  path: remappedPath,
                  absolutePath: tab.absolutePath.replace(path, result.path),
                  name: remappedPath.split("/").pop() || remappedPath,
                };
              }
              return {
                ...tab,
                id: tab.id.replace(path, result.path),
                path: remappedPath,
                title: tab.title.replace(path, result.path),
              };
            }
            return tab;
          }),
        );
        setActiveDocumentId(nextActiveDocumentId);
        await loadWorkspace();
        await refreshSourceControl();
        setBottomPanelOpen(true);
        setActiveBottomPanel("output");
        appendActivity(
          "success",
          "workspace",
          `Renamed ${path}`,
          `New path: ${result.path}`,
          result.path,
        );
      } catch (error) {
        const message = String(error);
        setWorkspaceError(message);
        setBottomPanelOpen(true);
        setActiveBottomPanel("problems");
        appendActivity("error", "workspace", `Rename failed for ${path}`, message, path);
      }
    },
    [activeDocumentId, adapter, appendActivity, loadWorkspace, refreshSourceControl, root],
  );

  const deletePath = useCallback(
    async (path: string) => {
      if (!window.confirm(`Delete ${path}? This cannot be undone.`)) {
        return;
      }
      try {
        await adapter.deletePath(root, path);
        setDocuments((current) => closeDeletedTabs(current, path));
        if (activeFilePath === path || activeFilePath?.startsWith(`${path}/`)) {
          setActiveDocumentId(null);
        }
        await loadWorkspace();
        await refreshSourceControl();
        setBottomPanelOpen(true);
        setActiveBottomPanel("output");
        appendActivity("warning", "workspace", `Deleted ${path}`, null, path);
      } catch (error) {
        const message = String(error);
        setWorkspaceError(message);
        setBottomPanelOpen(true);
        setActiveBottomPanel("problems");
        appendActivity("error", "workspace", `Delete failed for ${path}`, message, path);
      }
    },
    [activeFilePath, adapter, appendActivity, loadWorkspace, refreshSourceControl, root],
  );

  const problems = useMemo<WorkspaceProblemEntry[]>(() => {
    const nextProblems: WorkspaceProblemEntry[] = [];

    if (workspaceError) {
      nextProblems.push({
        id: "problem:workspace",
        severity: "error",
        source: "workspace",
        title: "Workspace refresh failed",
        detail: workspaceError,
      });
    }

    if (searchError) {
      nextProblems.push({
        id: "problem:search",
        severity: "error",
        source: "search",
        title: "Search failed",
        detail: searchError,
      });
    }

    if (sourceControlError) {
      nextProblems.push({
        id: "problem:source-control",
        severity: "error",
        source: "source-control",
        title: "Source control action failed",
        detail: sourceControlError,
      });
    }

    for (const tab of documents) {
      if (tab.kind !== "file") {
        continue;
      }

      if (tab.error) {
        nextProblems.push({
          id: `problem:file-error:${tab.path}`,
          severity: "error",
          source: "editor",
          title: `Unable to open ${tab.name}`,
          detail: tab.error,
          path: tab.path,
        });
      }

      if (tab.isBinary) {
        nextProblems.push({
          id: `problem:binary:${tab.path}`,
          severity: "warning",
          source: "editor",
          title: `${tab.name} is binary`,
          detail: "Binary files stay out of the embedded editor. Open this asset externally.",
          path: tab.path,
        });
      }

      if (tab.isTooLarge) {
        nextProblems.push({
          id: `problem:large:${tab.path}`,
          severity: "warning",
          source: "editor",
          title: `${tab.name} is too large for Monaco`,
          detail: "Use an external editor for this file or narrow the working set.",
          path: tab.path,
        });
      }
    }

    return [...terminalController.problems, ...nextProblems].slice(0, 120);
  }, [
    documents,
    searchError,
    sourceControlError,
    terminalController.problems,
    workspaceError,
  ]);

  const ports = useMemo<WorkspacePortEntry[]>(() => [], []);

  return {
    activePane,
    setActivePane,
    activeBottomPanel,
    setActiveBottomPanel,
    bottomPanelOpen,
    setBottomPanelOpen,
    snapshot,
    treeNodes,
    expandedPaths,
    loadingDirectories,
    workspaceLoading,
    workspaceError,
    documents,
    activeDocument,
    activeDocumentId,
    setActiveDocumentId,
    activeFilePath,
    revealRequest,
    consumeRevealRequest,
    searchDraft,
    setSearchDraft,
    searchLoading,
    searchError,
    searchResult,
    sourceControlState,
    sourceControlLoading,
    sourceControlError,
    activity,
    outputEntries,
    problems,
    ports,
    loadWorkspace,
    refreshSourceControl,
    openFile,
    toggleDirectory,
    updateFileContent,
    saveFile,
    closeDocument,
    runSearch,
    openDiff,
    stagePath: (path: string) => mutateSourceControl(adapter.stagePaths, path, "Staged"),
    unstagePath: (path: string) =>
      mutateSourceControl(adapter.unstagePaths, path, "Unstaged"),
    discardPath: (path: string) =>
      mutateSourceControl(adapter.discardPaths, path, "Discarded"),
    createFile,
    createDirectory,
    renamePath,
    deletePath,
  };
}
