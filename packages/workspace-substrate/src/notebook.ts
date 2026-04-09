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

export function isWorkspaceNotebookPath(path: string): boolean {
  return path.trim().toLowerCase().endsWith(".ipynb");
}

export function parseWorkspaceNotebookDocument(
  path: string,
  content: string,
): WorkspaceNotebookDocument | null {
  if (!isWorkspaceNotebookPath(path)) {
    return null;
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
  let notebook: NotebookRecord;
  try {
    notebook = JSON.parse(content) as NotebookRecord;
  } catch {
    return null;
  }

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
