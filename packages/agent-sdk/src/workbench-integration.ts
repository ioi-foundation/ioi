export const WORKBENCH_INTEGRATION_CONTRACT_SCHEMA_VERSION =
  "ioi.workbench-integration.v1" as const;

export type WorkbenchRuntimeTruthSource = "daemon-runtime";
export type WorkbenchProjectionOwner = "openvscode-workbench-adapter";

export interface WorkbenchRuntimeRefs {
  threadId?: string | null;
  runId?: string | null;
  turnId?: string | null;
  receiptRefs: string[];
  artifactRefs: string[];
  authorityRefs: string[];
  manifestRefs: string[];
  capabilityRefs: string[];
}

export interface WorkbenchProjectionContract {
  schemaVersion: typeof WORKBENCH_INTEGRATION_CONTRACT_SCHEMA_VERSION;
  runtimeTruthSource: WorkbenchRuntimeTruthSource;
  projectionOwner: WorkbenchProjectionOwner;
  ownsRuntimeState: false;
  runtimeRefs: WorkbenchRuntimeRefs;
}

export interface WorkbenchTextRange {
  startLineNumber: number;
  startColumn: number;
  endLineNumber: number;
  endColumn: number;
}

export interface WorkbenchActiveEditorRef {
  filePath: string;
  uri?: string;
  languageId?: string;
  selection?: WorkbenchTextRange | null;
  selectedTextHash?: string | null;
}

export interface WorkbenchDiagnosticRef {
  filePath: string;
  range: WorkbenchTextRange;
  severity: "hint" | "info" | "warning" | "error";
  message: string;
  source?: string | null;
  code?: string | null;
}

export interface WorkbenchScmState {
  provider: "git" | "none" | "unknown";
  branch?: string | null;
  dirty: boolean;
  changedFiles: string[];
  ahead?: number | null;
  behind?: number | null;
}

export interface WorkbenchTaskState {
  activeTaskLabels: string[];
  recentTaskLabels: string[];
  lastExitCode?: number | null;
  checkRefs: string[];
}

export interface WorkbenchTerminalState {
  activeTerminalName?: string | null;
  terminalCount: number;
  taskBacked: boolean;
}

export interface WorkbenchVisibleViewState {
  activityId?: string | null;
  sideBarViewId?: string | null;
  panelViewId?: string | null;
  activeEditorGroup?: string | null;
  activeIoiViewId?: string | null;
}

export interface WorkbenchInspectionLocator {
  kind: "vscode-command" | "vscode-view" | "editor-range" | "data-attribute" | "aria" | "dom";
  commandId?: string;
  viewId?: string;
  filePath?: string;
  range?: WorkbenchTextRange;
  selector?: string;
  accessibleName?: string;
}

export interface WorkbenchInspectionTarget {
  targetId: string;
  label: string;
  surface:
    | "activity-rail"
    | "command-center"
    | "explorer"
    | "editor"
    | "terminal"
    | "problems"
    | "chat"
    | "workflow"
    | "run-evidence"
    | "ioi-view";
  locators: WorkbenchInspectionLocator[];
  fallbackAllowed: boolean;
}

export interface WorkbenchInspectionTargetIndex
  extends WorkbenchProjectionContract {
  indexId: string;
  generatedAtMs: number;
  targets: WorkbenchInspectionTarget[];
}

export interface WorkbenchContextSnapshot extends WorkbenchProjectionContract {
  snapshotId: string;
  generatedAtMs: number;
  workspaceRoot: string;
  workspaceRef?: string | null;
  packageRef?: string | null;
  activeEditor?: WorkbenchActiveEditorRef | null;
  openEditors: WorkbenchActiveEditorRef[];
  diagnostics: WorkbenchDiagnosticRef[];
  scmState: WorkbenchScmState;
  taskState: WorkbenchTaskState;
  terminalState: WorkbenchTerminalState;
  visibleView: WorkbenchVisibleViewState;
  inspectionTargetIndexRef?: string | null;
}

export interface WorkbenchActionProposal extends WorkbenchProjectionContract {
  proposalId: string;
  proposedAtMs: number;
  sourceCommand: string;
  contextRef: string;
  requestedCapabilityRef: string;
  authorityScope: string;
  predictedEffect: string;
  requiresApproval: boolean;
  status: "proposed" | "blocked" | "approved" | "rejected";
}

export interface WorkbenchFileEdit {
  filePath: string;
  operation: "create" | "modify" | "delete" | "rename";
  oldPath?: string | null;
  patchRef?: string | null;
  contentRef?: string | null;
}

export interface WorkbenchEditProposal extends WorkbenchActionProposal {
  editProposalId: string;
  fileEdits: WorkbenchFileEdit[];
  diffRefs: string[];
  diagnosticsBeforeRefs: string[];
  expectedPostcondition: string;
  approvalProfileRef: string;
}

export interface WorkbenchApplyReceipt extends WorkbenchProjectionContract {
  receiptId: string;
  proposalId: string;
  appliedAtMs: number;
  appliedEdits: WorkbenchFileEdit[];
  diagnosticsAfterRefs: string[];
  scmStateAfter: WorkbenchScmState;
  status: "applied" | "blocked" | "failed";
  blockers: string[];
}

export interface WorkflowCodeGenerationRequest
  extends WorkbenchProjectionContract {
  requestId: string;
  requestedAtMs: number;
  workflowRef: string;
  packageRef: string;
  goal: string;
  boundModelCapabilityRef: string;
  boundToolCapabilityRefs: string[];
  targetWorkspace: string;
  authorityScope: string;
  evalProfileRef?: string | null;
  proposalOnly: boolean;
}

export interface WorkflowCodeGenerationReceipt
  extends WorkbenchProjectionContract {
  receiptId: string;
  requestRef: string;
  status: "proposed" | "applied" | "blocked" | "failed";
  createdFiles: string[];
  changedFiles: string[];
  diffRefs: string[];
  runRefs: string[];
  verificationRefs: string[];
  evalReceiptRefs: string[];
  promotionBlockers: string[];
}

export interface WorkbenchCommandRouteReceipt
  extends WorkbenchProjectionContract {
  receiptId: string;
  commandId: string;
  routedAtMs: number;
  route:
    | "editor-local"
    | "ioi-runtime-action"
    | "ioi-command-center"
    | "blocked";
  contextRef?: string | null;
  actionProposalRef?: string | null;
  status: "routed" | "blocked" | "failed";
  reason?: string | null;
}

export function emptyWorkbenchRuntimeRefs(
  overrides: Partial<WorkbenchRuntimeRefs> = {},
): WorkbenchRuntimeRefs {
  return {
    receiptRefs: [],
    artifactRefs: [],
    authorityRefs: [],
    manifestRefs: [],
    capabilityRefs: [],
    ...overrides,
  };
}

export function workbenchProjectionBase(
  runtimeRefs: Partial<WorkbenchRuntimeRefs> = {},
): WorkbenchProjectionContract {
  return {
    schemaVersion: WORKBENCH_INTEGRATION_CONTRACT_SCHEMA_VERSION,
    runtimeTruthSource: "daemon-runtime",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
    runtimeRefs: emptyWorkbenchRuntimeRefs(runtimeRefs),
  };
}

export function isWorkbenchProjectionContract(
  value: unknown,
): value is WorkbenchProjectionContract {
  if (!value || typeof value !== "object") {
    return false;
  }
  const candidate = value as Partial<WorkbenchProjectionContract>;
  return (
    candidate.schemaVersion === WORKBENCH_INTEGRATION_CONTRACT_SCHEMA_VERSION &&
    candidate.runtimeTruthSource === "daemon-runtime" &&
    candidate.projectionOwner === "openvscode-workbench-adapter" &&
    candidate.ownsRuntimeState === false &&
    Boolean(candidate.runtimeRefs) &&
    Array.isArray(candidate.runtimeRefs?.receiptRefs) &&
    Array.isArray(candidate.runtimeRefs?.artifactRefs) &&
    Array.isArray(candidate.runtimeRefs?.authorityRefs) &&
    Array.isArray(candidate.runtimeRefs?.manifestRefs) &&
    Array.isArray(candidate.runtimeRefs?.capabilityRefs)
  );
}

export function assertWorkbenchProjectionContract(
  value: unknown,
): asserts value is WorkbenchProjectionContract {
  if (!isWorkbenchProjectionContract(value)) {
    throw new TypeError(
      "Workbench integration objects must be daemon-runtime projections, not editor-owned runtime state.",
    );
  }
}
