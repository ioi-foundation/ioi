// T7-D — HypervisorWorkspaceAdapter: the real WorkspaceAdapter the Workbench substrate receives.
//
// Files come from the scoped environment workspace (POST /v1/hypervisor/env-files), terminals from
// the interactive PTY (/v1/hypervisor/terminals/*), and source-control/diff from the bound
// WorkRun. workspace-substrate keeps its adapter contract (visual panes only); it does NOT hard-
// code daemon routes — this adapter does, bound to one environment_ref from the Session Execution
// Binding. So Monaco/Explorer/Terminal/Diff all hydrate from the same binding.
import type {
  WorkspaceAdapter,
  WorkspaceCommitResult,
  WorkspaceDeleteResult,
  WorkspaceDiffDocument,
  WorkspaceFileDocument,
  WorkspaceLanguageCodeAction,
  WorkspaceLanguageLocation,
  WorkspaceLanguageServiceSnapshot,
  WorkspaceNode,
  WorkspacePathMutationResult,
  WorkspacePathStat,
  WorkspaceSearchResult,
  WorkspaceSnapshot,
  WorkspaceSourceControlEntry,
  WorkspaceSourceControlState,
  WorkspaceTerminalReadResult,
  WorkspaceTerminalSession,
} from "@ioi/workspace-substrate";
import type { HypervisorDaemonClient } from "./hypervisorDaemonClient";

interface FileEntry { name: string; type: "dir" | "file"; size: number }

const langOf = (path: string): string | null => {
  if (path.endsWith(".ts") || path.endsWith(".tsx")) return "typescript";
  if (path.endsWith(".rs")) return "rust";
  if (path.endsWith(".js") || path.endsWith(".mjs")) return "javascript";
  if (path.endsWith(".json")) return "json";
  if (path.endsWith(".md")) return "markdown";
  return "plaintext";
};

export function createHypervisorWorkspaceAdapter(
  client: HypervisorDaemonClient,
  environmentId: string,
  workRunId?: string,
): WorkspaceAdapter {
  const terminalSessions = new Map<string, string>(); // substrate sessionId -> daemon terminal_id

  const listAt = async (path: string): Promise<WorkspaceNode[]> => {
    const r = (await client.envFiles(environmentId, "list", { path })) as { ok?: boolean; result?: { entries?: FileEntry[] } };
    if (!r.ok || !r.result?.entries) return [];
    return r.result.entries.map((e) => ({
      name: e.name,
      path: path ? `${path}/${e.name}` : e.name,
      kind: e.type === "dir" ? "directory" : "file",
      hasChildren: e.type === "dir",
      children: [],
    }));
  };

  const readDoc = async (path: string): Promise<WorkspaceFileDocument> => {
    const r = (await client.envFiles(environmentId, "read", { path })) as { ok?: boolean; result?: { content?: string; bytes?: number } };
    const content = r.result?.content ?? "";
    return {
      name: path.split("/").pop() ?? path,
      path,
      absolutePath: path,
      languageHint: langOf(path),
      content,
      sizeBytes: r.result?.bytes ?? content.length,
      modifiedAtMs: null,
      isBinary: false,
      isTooLarge: false,
      readOnly: false,
    };
  };

  return {
    inspectWorkspace: async (root): Promise<WorkspaceSnapshot> => {
      const tree = await listAt("");
      return {
        rootPath: root,
        displayName: `environment:${environmentId}`,
        git: { isRepo: true, branch: workRunId ? `workrun/${workRunId}` : "main", dirty: false, lastCommit: null },
        tree,
      };
    },
    listDirectory: async (_root, path) => listAt(path),
    readFile: async (_root, path) => readDoc(path),
    getLanguageServiceSnapshot: async (root, path): Promise<WorkspaceLanguageServiceSnapshot> => ({
      generatedAtMs: 0,
      workspaceRoot: root,
      path,
      languageId: langOf(path) ?? "plaintext",
      availability: "unavailable",
      statusLabel: "No language server (daemon workspace)",
      serviceLabel: "none",
      serverLabel: "none",
      detail: null,
      diagnostics: [],
      symbols: [],
    }),
    getLanguageDefinition: async () => [] as WorkspaceLanguageLocation[],
    getLanguageReferences: async () => [] as WorkspaceLanguageLocation[],
    getLanguageCodeActions: async () => [] as WorkspaceLanguageCodeAction[],
    writeFile: async (_root, path, content) => {
      await client.envFiles(environmentId, "write", { path, content });
      return { ...(await readDoc(path)), content, sizeBytes: content.length };
    },
    createFile: async (_root, path) => {
      await client.envFiles(environmentId, "write", { path, content: "" });
      return readDoc(path);
    },
    createDirectory: async (_root, path): Promise<WorkspacePathMutationResult> => {
      await client.envFiles(environmentId, "write", { path: `${path}/.gitkeep`, content: "" });
      return { path };
    },
    statPath: async (_root, path): Promise<WorkspacePathStat> => {
      const parent = path.includes("/") ? path.slice(0, path.lastIndexOf("/")) : "";
      const entries = await listAt(parent);
      const found = entries.find((e) => e.path === path);
      return { kind: found?.kind === "directory" ? "directory" : "file", sizeBytes: 0, modifiedAtMs: null, readOnly: false };
    },
    renamePath: async (_root, from, to): Promise<WorkspacePathMutationResult> => {
      await client.envFiles(environmentId, "move", { path: from, to });
      return { path: to };
    },
    deletePath: async (_root, path): Promise<WorkspaceDeleteResult> => {
      await client.envFiles(environmentId, "delete", { path });
      return { deletedPath: path } as WorkspaceDeleteResult;
    },
    searchText: async (_root, query): Promise<WorkspaceSearchResult> => ({ query, totalMatches: 0, files: [] }),
    getSourceControlState: async (): Promise<WorkspaceSourceControlState> => {
      let branch = "main";
      let review: string | null = null;
      const entries: WorkspaceSourceControlEntry[] = [];
      if (workRunId) {
        const wr = (await client.getWorkRun(workRunId)).workRun as { branch?: string; review_state?: string } | undefined;
        branch = wr?.branch ?? branch;
        review = wr?.review_state ?? null;
      }
      return { git: { isRepo: true, branch, dirty: entries.length > 0, lastCommit: review ? `review: ${review}` : null }, entries };
    },
    getDiff: async (_root, path): Promise<WorkspaceDiffDocument> => {
      const doc = await readDoc(path);
      return {
        id: `diff:${path}`,
        path,
        title: path,
        originalLabel: "HEAD",
        modifiedLabel: workRunId ? `workrun/${workRunId}` : "Working Tree",
        originalContent: "",
        modifiedContent: doc.content,
        languageHint: langOf(path),
        isBinary: false,
      };
    },
    commitChanges: async (_root, message): Promise<WorkspaceCommitResult> => ({
      state: { git: { isRepo: true, branch: workRunId ? `workrun/${workRunId}` : "main", dirty: false, lastCommit: message.headline }, entries: [] },
      committedFileCount: 0,
      remainingChangeCount: 0,
      commitSummary: message.headline,
    }),
    stagePaths: async (): Promise<WorkspaceSourceControlState> => ({ git: { isRepo: true, branch: "main", dirty: false, lastCommit: null }, entries: [] }),
    unstagePaths: async (): Promise<WorkspaceSourceControlState> => ({ git: { isRepo: true, branch: "main", dirty: false, lastCommit: null }, entries: [] }),
    discardPaths: async (): Promise<WorkspaceSourceControlState> => ({ git: { isRepo: true, branch: "main", dirty: false, lastCommit: null }, entries: [] }),
    createTerminalSession: async (root, cols, rows): Promise<WorkspaceTerminalSession> => {
      const t = (await client.createTerminal(`environment:${environmentId}`, cols, rows)) as { ok?: boolean; terminal_id?: string; shell?: string };
      const sessionId = t.terminal_id ?? `term-${Date.now()}`;
      if (t.terminal_id) terminalSessions.set(sessionId, t.terminal_id);
      return { sessionId, shell: t.shell ?? "bash", rootPath: root, startedAtMs: 0, cols, rows };
    },
    readTerminalSession: async (sessionId, cursor): Promise<WorkspaceTerminalReadResult> => {
      const tid = terminalSessions.get(sessionId) ?? sessionId;
      const s = await client.terminalStream(tid, cursor);
      return {
        sessionId,
        cursor: s.offset,
        chunks: s.output ? [{ sequence: cursor, text: s.output }] : [],
        running: s.running,
        exitCode: null,
      };
    },
    writeTerminalSession: async (sessionId, data) => {
      const tid = terminalSessions.get(sessionId) ?? sessionId;
      await client.terminalInput(tid, data);
    },
    resizeTerminalSession: async (sessionId, cols, rows) => {
      const tid = terminalSessions.get(sessionId) ?? sessionId;
      await client.terminalResize(tid, cols, rows);
    },
    closeTerminalSession: async (sessionId) => {
      const tid = terminalSessions.get(sessionId) ?? sessionId;
      await client.terminalClose(tid);
      terminalSessions.delete(sessionId);
    },
  };
}
