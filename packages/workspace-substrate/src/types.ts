export type WorkspacePane = "files" | "search" | "source-control";
export type WorkspaceLayoutMode = "full" | "embedded" | "compact";
export type WorkspaceBottomPanel = "terminal" | "problems" | "output" | "ports";

export interface WorkspaceActivityEntry {
  id: string;
  kind: "info" | "success" | "warning" | "error";
  source: string;
  title: string;
  detail: string | null;
  timestampMs: number;
  path?: string;
  line?: number;
  column?: number;
}

export interface WorkspaceProblemEntry {
  id: string;
  severity: "error" | "warning" | "info";
  source: string;
  title: string;
  detail: string;
  path?: string;
  line?: number;
  column?: number;
}

export interface WorkspacePortEntry {
  id: string;
  label: string;
  status: "idle" | "active";
  description: string;
  value?: string;
}

export interface WorkspaceGitSummary {
  isRepo: boolean;
  branch: string | null;
  dirty: boolean;
  lastCommit: string | null;
}

export interface WorkspaceNode {
  name: string;
  path: string;
  kind: "directory" | "file";
  hasChildren: boolean;
  children: WorkspaceNode[];
}

export interface WorkspaceSnapshot {
  rootPath: string;
  displayName: string;
  git: WorkspaceGitSummary;
  tree: WorkspaceNode[];
}

export interface WorkspaceFileDocument {
  name: string;
  path: string;
  absolutePath: string;
  languageHint: string | null;
  content: string;
  sizeBytes: number;
  modifiedAtMs: number | null;
  isBinary: boolean;
  isTooLarge: boolean;
  readOnly: boolean;
}

export interface WorkspaceNotebookCell {
  id: string;
  index: number;
  cellType: string;
  source: string;
  sourceKind: "string" | "array";
  executionCount: number | null;
  outputCount: number;
  outputPreview: string[];
  metadataEntryCount: number;
}

export interface WorkspaceNotebookDocument {
  path: string;
  nbformat: number;
  nbformatMinor: number;
  language: string | null;
  kernelDisplayName: string | null;
  cellCount: number;
  cells: WorkspaceNotebookCell[];
}

export interface WorkspaceSearchMatch {
  path: string;
  line: number;
  column: number;
  preview: string;
}

export interface WorkspaceSearchFileResult {
  path: string;
  matchCount: number;
  matches: WorkspaceSearchMatch[];
}

export interface WorkspaceSearchResult {
  query: string;
  totalMatches: number;
  files: WorkspaceSearchFileResult[];
}

export interface WorkspaceSourceControlEntry {
  path: string;
  originalPath: string | null;
  x: string;
  y: string;
}

export interface WorkspaceSourceControlState {
  git: WorkspaceGitSummary;
  entries: WorkspaceSourceControlEntry[];
}

export interface WorkspaceCommitMessage {
  headline: string;
  body?: string | null;
}

export interface WorkspaceCommitResult {
  state: WorkspaceSourceControlState;
  committedFileCount: number;
  remainingChangeCount: number;
  commitSummary: string;
}

export interface WorkspaceDiffDocument {
  id: string;
  path: string;
  title: string;
  originalLabel: string;
  modifiedLabel: string;
  originalContent: string;
  modifiedContent: string;
  languageHint: string | null;
  isBinary: boolean;
}

export interface WorkspaceDeleteResult {
  deletedPath: string;
}

export interface WorkspacePathMutationResult {
  path: string;
}

export interface WorkspacePathStat {
  kind: "file" | "directory";
  sizeBytes: number;
  modifiedAtMs: number | null;
  readOnly: boolean;
}

export interface WorkspaceLanguageDiagnostic {
  severity: "error" | "warning" | "info";
  title: string;
  detail: string;
  code?: string | null;
  source?: string | null;
  path: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
}

export interface WorkspaceLanguageLocation {
  path: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
}

export interface WorkspaceLanguageTextEdit {
  path: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  newText: string;
}

export interface WorkspaceLanguageCodeAction {
  title: string;
  kind?: string | null;
  isPreferred: boolean;
  disabledReason?: string | null;
  edits: WorkspaceLanguageTextEdit[];
}

export interface WorkspaceLanguageSymbol {
  name: string;
  kind: string;
  detail?: string | null;
  path: string;
  line: number;
  column: number;
  endLine: number;
  endColumn: number;
  children: WorkspaceLanguageSymbol[];
}

export interface WorkspaceLanguageServiceSnapshot {
  generatedAtMs: number;
  workspaceRoot: string;
  path: string;
  languageId: string;
  availability: string;
  statusLabel: string;
  serviceLabel: string;
  serverLabel?: string | null;
  detail?: string | null;
  diagnostics: WorkspaceLanguageDiagnostic[];
  symbols: WorkspaceLanguageSymbol[];
}

export interface WorkspaceTerminalSession {
  sessionId: string;
  shell: string;
  rootPath: string;
  startedAtMs: number;
  cols: number;
  rows: number;
}

export interface WorkspaceTerminalOutputChunk {
  sequence: number;
  text: string;
}

export interface WorkspaceTerminalReadResult {
  sessionId: string;
  cursor: number;
  chunks: WorkspaceTerminalOutputChunk[];
  running: boolean;
  exitCode: number | null;
}

export interface WorkspaceTerminalController {
  root: string;
  enabled: boolean;
  session: WorkspaceTerminalSession | null;
  running: boolean;
  exitCode: number | null;
  error: string | null;
  activityEntries: WorkspaceActivityEntry[];
  outputEntries: WorkspaceActivityEntry[];
  problems: WorkspaceProblemEntry[];
  getHistory: () => string;
  subscribe: (listener: (text: string) => void) => () => void;
  subscribeState: (listener: () => void) => () => void;
  start: () => void;
  stop: () => void;
  write: (data: string) => Promise<void>;
  resize: (cols: number, rows: number) => Promise<void>;
}

export interface WorkspaceOpenRequest {
  path: string;
  line?: number;
  column?: number;
}

export interface WorkspaceSelectionPayload {
  path: string;
  selection: string;
}

export interface WorkspaceAdapter {
  inspectWorkspace: (root: string) => Promise<WorkspaceSnapshot>;
  listDirectory: (root: string, path: string) => Promise<WorkspaceNode[]>;
  readFile: (root: string, path: string) => Promise<WorkspaceFileDocument>;
  getLanguageServiceSnapshot: (
    root: string,
    path: string,
    content?: string,
  ) => Promise<WorkspaceLanguageServiceSnapshot>;
  getLanguageDefinition: (
    root: string,
    path: string,
    line: number,
    column: number,
    content?: string,
  ) => Promise<WorkspaceLanguageLocation[]>;
  getLanguageReferences: (
    root: string,
    path: string,
    line: number,
    column: number,
    content?: string,
  ) => Promise<WorkspaceLanguageLocation[]>;
  getLanguageCodeActions: (
    root: string,
    path: string,
    line: number,
    column: number,
    endLine: number,
    endColumn: number,
    content?: string,
  ) => Promise<WorkspaceLanguageCodeAction[]>;
  writeFile: (
    root: string,
    path: string,
    content: string,
  ) => Promise<WorkspaceFileDocument>;
  createFile: (root: string, path: string) => Promise<WorkspaceFileDocument>;
  createDirectory: (root: string, path: string) => Promise<WorkspacePathMutationResult>;
  statPath: (root: string, path: string) => Promise<WorkspacePathStat>;
  renamePath: (
    root: string,
    from: string,
    to: string,
  ) => Promise<WorkspacePathMutationResult>;
  deletePath: (root: string, path: string) => Promise<WorkspaceDeleteResult>;
  searchText: (root: string, query: string) => Promise<WorkspaceSearchResult>;
  getSourceControlState: (root: string) => Promise<WorkspaceSourceControlState>;
  getDiff: (
    root: string,
    path: string,
    staged: boolean,
  ) => Promise<WorkspaceDiffDocument>;
  commitChanges: (
    root: string,
    message: WorkspaceCommitMessage,
  ) => Promise<WorkspaceCommitResult>;
  stagePaths: (root: string, paths: string[]) => Promise<WorkspaceSourceControlState>;
  unstagePaths: (root: string, paths: string[]) => Promise<WorkspaceSourceControlState>;
  discardPaths: (root: string, paths: string[]) => Promise<WorkspaceSourceControlState>;
  createTerminalSession: (
    root: string,
    cols: number,
    rows: number,
  ) => Promise<WorkspaceTerminalSession>;
  readTerminalSession: (
    sessionId: string,
    cursor: number,
  ) => Promise<WorkspaceTerminalReadResult>;
  writeTerminalSession: (sessionId: string, data: string) => Promise<void>;
  resizeTerminalSession: (
    sessionId: string,
    cols: number,
    rows: number,
  ) => Promise<void>;
  closeTerminalSession: (sessionId: string) => Promise<void>;
}

export interface WorkspaceRailProps {
  activePane: WorkspacePane;
  onSelectPane: (pane: WorkspacePane) => void;
}

export interface WorkspaceExplorerPaneProps {
  tree: WorkspaceNode[];
  activePath: string | null;
  expandedPaths: Record<string, boolean>;
  loadingDirectories: Record<string, boolean>;
  git: WorkspaceGitSummary;
  rootPath: string;
  eyebrow?: string;
  title?: string;
  readOnly?: boolean;
  showGitSummary?: boolean;
  showRefreshButton?: boolean;
  onToggleDirectory: (node: WorkspaceNode) => void;
  onOpenFile: (path: string) => void;
  onRefresh: () => void;
  onCreateFile: () => void;
  onCreateDirectory: () => void;
  onRenamePath: (path: string) => void;
  onDeletePath: (path: string) => void;
}

export interface WorkspaceSearchPaneProps {
  searchDraft: string;
  searchLoading: boolean;
  searchError: string | null;
  searchResult: WorkspaceSearchResult | null;
  onSearchDraftChange: (value: string) => void;
  onRunSearch: () => void;
  onOpenMatch: (match: WorkspaceSearchMatch) => void;
}

export interface WorkspaceSourceControlPaneProps {
  state: WorkspaceSourceControlState | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
  onOpenDiff: (path: string, staged: boolean) => void;
  onOpenFile: (path: string) => void;
  onStage: (path: string) => void;
  onUnstage: (path: string) => void;
  onDiscard: (path: string) => void;
}

export interface WorkspaceBottomPanelProps {
  terminal: WorkspaceTerminalController;
  rootPath: string;
  visiblePanels: WorkspaceBottomPanel[];
  activePanel: WorkspaceBottomPanel;
  isOpen: boolean;
  outputEntries: WorkspaceActivityEntry[];
  problems: WorkspaceProblemEntry[];
  ports: WorkspacePortEntry[];
  onSelectPanel: (panel: WorkspaceBottomPanel) => void;
  onToggleOpen: () => void;
  onOpenRequest: (request: WorkspaceOpenRequest) => void;
}
