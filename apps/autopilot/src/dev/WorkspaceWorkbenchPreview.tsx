import { WorkspaceHost, type WorkspaceAdapter, type WorkspaceCommitMessage, type WorkspaceCommitResult, type WorkspaceDeleteResult, type WorkspaceDiffDocument, type WorkspaceFileDocument, type WorkspaceLanguageCodeAction, type WorkspaceLanguageLocation, type WorkspaceLanguageServiceSnapshot, type WorkspaceNode, type WorkspacePathMutationResult, type WorkspaceSearchResult, type WorkspaceSnapshot, type WorkspaceSourceControlState, type WorkspaceTerminalReadResult, type WorkspaceTerminalSession } from "@ioi/workspace-substrate";

const ROOT = "/workspace/src-tauri";
const ROOT_NODE = "SRC-TAURI";
const ACTIVE_CHILD = `${ROOT_NODE}/src-tauri`;

const TREE: WorkspaceNode[] = [
  {
    name: ROOT_NODE,
    path: ROOT_NODE,
    kind: "directory",
    hasChildren: true,
    children: [
      {
        name: "src-tauri",
        path: ACTIVE_CHILD,
        kind: "directory",
        hasChildren: true,
        children: [
          {
            name: "src",
            path: `${ACTIVE_CHILD}/src`,
            kind: "directory",
            hasChildren: false,
            children: [],
          },
        ],
      },
    ],
  },
];

const SNAPSHOT: WorkspaceSnapshot = {
  rootPath: ROOT,
  displayName: "src-tauri",
  git: {
    isRepo: true,
    branch: "main",
    dirty: false,
    lastCommit: "Initial workspace scaffold",
  },
  tree: TREE,
};

const EMPTY_LANGUAGE_SNAPSHOT: WorkspaceLanguageServiceSnapshot = {
  generatedAtMs: Date.now(),
  workspaceRoot: ROOT,
  path: `${ACTIVE_CHILD}/src/main.rs`,
  languageId: "rust",
  availability: "ready",
  statusLabel: "Ready",
  serviceLabel: "Rust Analyzer",
  serverLabel: "Rust Analyzer",
  detail: null,
  diagnostics: [],
  symbols: [],
};

const EMPTY_SCM_STATE: WorkspaceSourceControlState = {
  git: SNAPSHOT.git,
  entries: [],
};

function createPreviewFile(path: string): WorkspaceFileDocument {
  const name = path.split("/").pop() ?? path;
  return {
    name,
    path,
    absolutePath: `${ROOT}/${path}`,
    languageHint: path.endsWith(".rs") ? "rust" : "plaintext",
    content: `fn main() {\n    println!(\"Hello from ${name}\");\n}\n`,
    sizeBytes: 48,
    modifiedAtMs: Date.now(),
    isBinary: false,
    isTooLarge: false,
    readOnly: false,
  };
}

function notImplementedMutation(path: string): Promise<WorkspacePathMutationResult> {
  return Promise.resolve({ path });
}

function previewDiff(path: string): WorkspaceDiffDocument {
  return {
    id: `diff:${path}`,
    path,
    title: path,
    originalLabel: "HEAD",
    modifiedLabel: "Working Tree",
    originalContent: "fn main() {\n    println!(\"before\");\n}\n",
    modifiedContent: "fn main() {\n    println!(\"after\");\n}\n",
    languageHint: "rust",
    isBinary: false,
  };
}

const previewAdapter: WorkspaceAdapter = {
  inspectWorkspace: async () => SNAPSHOT,
  listDirectory: async (_root, path) => {
    if (path === ROOT_NODE) {
      return TREE[0].children;
    }
    if (path === ACTIVE_CHILD) {
      return TREE[0].children[0].children;
    }
    return [];
  },
  readFile: async (_root, path) => createPreviewFile(path),
  getLanguageServiceSnapshot: async () => EMPTY_LANGUAGE_SNAPSHOT,
  getLanguageDefinition: async () => [] as WorkspaceLanguageLocation[],
  getLanguageReferences: async () => [] as WorkspaceLanguageLocation[],
  getLanguageCodeActions: async () => [] as WorkspaceLanguageCodeAction[],
  writeFile: async (_root, path, content) => ({
    ...createPreviewFile(path),
    content,
    sizeBytes: content.length,
  }),
  createFile: async (_root, path) => createPreviewFile(path),
  createDirectory: async (_root, path) => notImplementedMutation(path),
  statPath: async (_root, path) => ({
    kind: path.endsWith(".rs") ? "file" : "directory",
    sizeBytes: 48,
    modifiedAtMs: Date.now(),
    readOnly: false,
  }),
  renamePath: async (_root, _from, to) => notImplementedMutation(to),
  deletePath: async (_root, path) => ({ deletedPath: path } as WorkspaceDeleteResult),
  searchText: async (_root, query) =>
    ({
      query,
      totalMatches: 1,
      files: [
        {
          path: `${ACTIVE_CHILD}/src/main.rs`,
          matchCount: 1,
          matches: [
            {
              path: `${ACTIVE_CHILD}/src/main.rs`,
              line: 1,
              column: 1,
              preview: "fn main() {",
            },
          ],
        },
      ],
    }) as WorkspaceSearchResult,
  getSourceControlState: async () => EMPTY_SCM_STATE,
  getDiff: async (_root, path) => previewDiff(path),
  commitChanges: async (_root, message) =>
    ({
      state: EMPTY_SCM_STATE,
      committedFileCount: 1,
      remainingChangeCount: 0,
      commitSummary: (message as WorkspaceCommitMessage).headline,
    }) as WorkspaceCommitResult,
  stagePaths: async () => EMPTY_SCM_STATE,
  unstagePaths: async () => EMPTY_SCM_STATE,
  discardPaths: async () => EMPTY_SCM_STATE,
  createTerminalSession: async () =>
    ({
      sessionId: "preview-terminal",
      shell: "/bin/bash",
      rootPath: ROOT,
      startedAtMs: Date.now(),
      cols: 80,
      rows: 24,
    }) as WorkspaceTerminalSession,
  readTerminalSession: async () =>
    ({
      sessionId: "preview-terminal",
      chunks: [],
      cursor: 0,
      running: false,
      exitCode: null,
    }) as WorkspaceTerminalReadResult,
  writeTerminalSession: async () => undefined,
  resizeTerminalSession: async () => undefined,
  closeTerminalSession: async () => undefined,
};

export function WorkspaceWorkbenchPreview() {
  return (
    <main
      style={{
        minHeight: "100vh",
        background: "#111318",
        display: "flex",
        alignItems: "stretch",
        justifyContent: "center",
        padding: 0,
      }}
    >
      <section style={{ width: "100%", minHeight: "100vh" }}>
        <WorkspaceHost
          adapter={previewAdapter}
          root={ROOT}
          title="Workspace for src-tauri"
          showHeader={false}
          showBottomPanel={false}
          initialSnapshot={SNAPSHOT}
          initialState={{
            activePane: "files",
            activeBottomPanel: "output",
            bottomPanelOpen: false,
            expandedPaths: {
              [ROOT_NODE]: true,
              [ACTIVE_CHILD]: false,
            },
            documents: [],
            activeDocumentPath: null,
          }}
        />
      </section>
    </main>
  );
}
