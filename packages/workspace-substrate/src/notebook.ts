import type { WorkspaceNotebookCell, WorkspaceNotebookDocument } from "./types";

type NotebookSource = string | string[];

type NotebookCellRecord = {
  id?: string;
  cell_type?: string;
  source?: NotebookSource;
  execution_count?: number | null;
  outputs?: unknown[];
  metadata?: Record<string, unknown> | null;
};

type NotebookRecord = {
  nbformat?: number;
  nbformat_minor?: number;
  metadata?: {
    language_info?: {
      name?: string;
    } | null;
    kernelspec?: {
      display_name?: string;
    } | null;
  } | null;
  cells?: NotebookCellRecord[];
};

type HypervisorReplayCellRecord = {
  id?: string;
  cell_kind?: string;
  status?: string;
  read_only_replay?: boolean;
  title?: string;
  summary?: string | null;
  tool_name?: string | null;
  tool_call_id?: string | null;
  snapshot_id?: string | null;
  file_paths?: unknown;
  operation_count?: number;
  restore_preview_endpoint?: string | null;
  restore_apply_endpoint?: string | null;
  receipt_refs?: unknown;
  artifact_refs?: unknown;
  rollback_refs?: unknown;
  policy_decision_refs?: unknown;
};

type HypervisorReplayRecord = {
  schema_version?: string;
  status?: string;
  read_only_replay_mode?: boolean;
  receipt_backed_cell_count?: number;
  cells?: HypervisorReplayCellRecord[];
};

function sourceToString(source: NotebookSource | undefined): string {
  if (Array.isArray(source)) {
    return source.join("");
  }
  return typeof source === "string" ? source : "";
}

function sourceKind(source: NotebookSource | undefined): "string" | "array" {
  return Array.isArray(source) ? "array" : "string";
}

function sourceFromString(value: string, kind: "string" | "array"): NotebookSource {
  if (kind === "string") {
    return value;
  }
  return value.match(/[^\n]*\n|[^\n]+/g) ?? [];
}

function outputPreview(output: unknown): string | null {
  if (!output || typeof output !== "object") {
    return null;
  }

  const record = output as Record<string, unknown>;
  const streamText = record.text;
  if (Array.isArray(streamText)) {
    const text = streamText.join("").trim();
    if (text) {
      return text;
    }
  } else if (typeof streamText === "string" && streamText.trim()) {
    return streamText.trim();
  }

  const data = record.data;
  if (data && typeof data === "object") {
    const textPlain = (data as Record<string, unknown>)["text/plain"];
    if (Array.isArray(textPlain)) {
      const text = textPlain.join("").trim();
      if (text) {
        return text;
      }
    } else if (typeof textPlain === "string" && textPlain.trim()) {
      return textPlain.trim();
    }
  }

  const errorName = typeof record.ename === "string" ? record.ename.trim() : "";
  const errorValue = typeof record.evalue === "string" ? record.evalue.trim() : "";
  if (errorName || errorValue) {
    return [errorName, errorValue].filter(Boolean).join(": ");
  }

  return typeof record.output_type === "string" && record.output_type.trim()
    ? record.output_type.trim()
    : null;
}

function notebookCellId(cell: NotebookCellRecord, index: number): string {
  const explicit = typeof cell.id === "string" ? cell.id.trim() : "";
  return explicit || `cell-${index + 1}`;
}

function isHypervisorReplayPath(path: string): boolean {
  return path.trim().toLowerCase().endsWith(".hypervisor");
}

export function isWorkspaceNotebookPath(path: string): boolean {
  const normalized = path.trim().toLowerCase();
  return normalized.endsWith(".ipynb") || normalized.endsWith(".hypervisor");
}

export function parseWorkspaceNotebookDocument(
  path: string,
  content: string,
): WorkspaceNotebookDocument | null {
  if (!isWorkspaceNotebookPath(path)) {
    return null;
  }

  if (isHypervisorReplayPath(path)) {
    return parseHypervisorReplayNotebookDocument(path, content);
  }

  let notebook: NotebookRecord;
  try {
    notebook = JSON.parse(content) as NotebookRecord;
  } catch {
    return null;
  }

  const rawCells = Array.isArray(notebook.cells) ? notebook.cells : [];
  const cells: WorkspaceNotebookCell[] = rawCells.map((cell, index) => {
    const previews = Array.isArray(cell.outputs)
      ? cell.outputs
          .map(outputPreview)
          .filter((entry): entry is string => Boolean(entry))
          .slice(0, 3)
      : [];
    return {
      id: notebookCellId(cell, index),
      index,
      cellType: typeof cell.cell_type === "string" ? cell.cell_type : "code",
      source: sourceToString(cell.source),
      sourceKind: sourceKind(cell.source),
      executionCount:
        typeof cell.execution_count === "number" ? cell.execution_count : null,
      outputCount: Array.isArray(cell.outputs) ? cell.outputs.length : 0,
      outputPreview: previews,
      metadataEntryCount:
        cell.metadata && typeof cell.metadata === "object"
          ? Object.keys(cell.metadata).length
          : 0,
    };
  });

  return {
    path,
    documentKind: "jupyter",
    nbformat: typeof notebook.nbformat === "number" ? notebook.nbformat : 4,
    nbformatMinor:
      typeof notebook.nbformat_minor === "number" ? notebook.nbformat_minor : 5,
    language:
      typeof notebook.metadata?.language_info?.name === "string"
        ? notebook.metadata.language_info.name
        : null,
    kernelDisplayName:
      typeof notebook.metadata?.kernelspec?.display_name === "string"
        ? notebook.metadata.kernelspec.display_name
        : null,
    cellCount: cells.length,
    cells,
  };
}

export function updateWorkspaceNotebookCellSource(
  content: string,
  cellId: string,
  nextSource: string,
): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content) as unknown;
  } catch {
    return null;
  }

  if (isHypervisorReplayNotebookRecord(parsed)) {
    return null;
  }

  if (!parsed || typeof parsed !== "object") {
    return null;
  }

  const notebook = parsed as NotebookRecord;
  if (!Array.isArray(notebook.cells)) {
    return null;
  }

  const cellIndex = notebook.cells.findIndex(
    (cell, index) => notebookCellId(cell, index) === cellId,
  );
  if (cellIndex < 0) {
    return null;
  }

  const target = notebook.cells[cellIndex]!;
  target.source = sourceFromString(nextSource, sourceKind(target.source));
  return `${JSON.stringify(notebook, null, 2)}\n`;
}

function parseHypervisorReplayNotebookDocument(
  path: string,
  content: string,
): WorkspaceNotebookDocument | null {
  let replay: HypervisorReplayRecord;
  try {
    replay = JSON.parse(content) as HypervisorReplayRecord;
  } catch {
    return null;
  }

  if (!isHypervisorReplayNotebookRecord(replay)) {
    return null;
  }

  const cells = (Array.isArray(replay.cells) ? replay.cells : []).map(
    (cell, index): WorkspaceNotebookCell => {
      const receiptRefs = stringArray(cell.receipt_refs);
      const artifactRefs = stringArray(cell.artifact_refs);
      const rollbackRefs = stringArray(cell.rollback_refs);
      const policyDecisionRefs = stringArray(cell.policy_decision_refs);
      const outputPreview = [
        receiptRefs.length ? `${receiptRefs.length} receipt refs` : null,
        artifactRefs.length ? `${artifactRefs.length} artifact refs` : null,
        rollbackRefs.length ? `${rollbackRefs.length} rollback refs` : null,
        policyDecisionRefs.length
          ? `${policyDecisionRefs.length} policy decision refs`
          : null,
      ].filter((entry): entry is string => Boolean(entry));

      return {
        id:
          typeof cell.id === "string" && cell.id.trim()
            ? cell.id.trim()
            : `hypervisor-cell-${index + 1}`,
        index,
        cellType:
          stringField(cell.cell_kind) || "hypervisor_replay",
        source: hypervisorReplayCellSource(cell, {
          receiptRefs,
          artifactRefs,
          rollbackRefs,
          policyDecisionRefs,
        }),
        sourceKind: "string",
        executionCount: null,
        outputCount: outputPreview.length,
        outputPreview,
        metadataEntryCount: Object.keys(cell).length,
        readOnly: true,
      };
    },
  );

  return {
    path,
    documentKind: "hypervisor_replay",
    nbformat: 4,
    nbformatMinor: 5,
    language: "hypervisor-replay",
    kernelDisplayName: "Hypervisor Signed Replay",
    readOnlyReplayMode: Boolean(replay.read_only_replay_mode),
    receiptBackedCellCount:
      typeof replay.receipt_backed_cell_count === "number"
          ? replay.receipt_backed_cell_count
          : cells.filter((cell) =>
              cell.outputPreview.some((preview) => preview.includes("receipt")),
            ).length,
    cellCount: cells.length,
    cells,
  };
}

function isHypervisorReplayNotebookRecord(
  value: unknown,
): value is HypervisorReplayRecord {
  if (!value || typeof value !== "object") {
    return false;
  }
  const record = value as HypervisorReplayRecord;
  const schema = String(record.schema_version ?? "");
  return schema.includes("signed-replay-notebook");
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter(
        (entry): entry is string =>
          typeof entry === "string" && Boolean(entry.trim()),
      )
    : [];
}

function hypervisorReplayCellSource(
  cell: HypervisorReplayCellRecord,
  refs: {
    receiptRefs: string[];
    artifactRefs: string[];
    rollbackRefs: string[];
    policyDecisionRefs: string[];
  },
): string {
  const title = stringField(cell.title) || "Hypervisor replay cell";
  const lines = [`# ${title}`];
  const summary = stringField(cell.summary);
  const status = stringField(cell.status);
  const toolName = stringField(cell.tool_name);
  const toolCallId = stringField(cell.tool_call_id);
  const snapshotId = stringField(cell.snapshot_id);
  const filePaths = stringArray(cell.file_paths);
  const restorePreviewEndpoint = stringField(cell.restore_preview_endpoint);
  const restoreApplyEndpoint = stringField(cell.restore_apply_endpoint);

  if (summary) lines.push("", summary);
  if (status) lines.push("", `Status: ${status}`);
  if (toolName) lines.push(`Tool: ${toolName}`);
  if (toolCallId) lines.push(`Tool call: ${toolCallId}`);
  if (snapshotId) lines.push(`Snapshot: ${snapshotId}`);
  if (typeof cell.operation_count === "number") {
    lines.push(`Operations: ${cell.operation_count}`);
  }
  if (filePaths.length) lines.push(`Files: ${filePaths.join(", ")}`);
  if (refs.receiptRefs.length) {
    lines.push(`Receipts: ${refs.receiptRefs.join(", ")}`);
  }
  if (refs.artifactRefs.length) {
    lines.push(`Artifacts: ${refs.artifactRefs.join(", ")}`);
  }
  if (refs.rollbackRefs.length) {
    lines.push(`Rollback refs: ${refs.rollbackRefs.join(", ")}`);
  }
  if (refs.policyDecisionRefs.length) {
    lines.push(`Policy decisions: ${refs.policyDecisionRefs.join(", ")}`);
  }
  if (restorePreviewEndpoint) {
    lines.push(`Restore preview: ${restorePreviewEndpoint}`);
  }
  if (restoreApplyEndpoint) {
    lines.push(`Restore apply: ${restoreApplyEndpoint}`);
  }
  return `${lines.join("\n")}\n`;
}
