import { useMemo } from "react";
import type { WorkspaceFileTab } from "../useWorkspaceSession";
import {
  parseWorkspaceNotebookDocument,
  updateWorkspaceNotebookCellSource,
} from "../notebook";

interface WorkspaceNotebookPaneProps {
  document: WorkspaceFileTab;
  onChangeFileContent: (path: string, content: string) => void;
  onAttachSelection?: (payload: { path: string; selection: string }) => void;
}

function humanizeCellType(value: string): string {
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function WorkspaceNotebookPane({
  document,
  onChangeFileContent,
  onAttachSelection,
}: WorkspaceNotebookPaneProps) {
  const notebook = useMemo(
    () => parseWorkspaceNotebookDocument(document.path, document.content),
    [document.content, document.path],
  );

  if (!notebook) {
    return (
      <div className="workspace-editor-empty">
        <div>
          <h3>Notebook preview unavailable</h3>
          <p>
            This `.ipynb` file is not valid notebook JSON yet. Fix the document
            structure in an external editor or restore a valid notebook payload.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="workspace-notebook">
      <div className="workspace-notebook-summary">
        <span className="workspace-chip">{notebook.cellCount} cells</span>
        <span className="workspace-chip">nbformat {notebook.nbformat}.{notebook.nbformatMinor}</span>
        {notebook.language ? (
          <span className="workspace-chip">{notebook.language}</span>
        ) : null}
        {notebook.kernelDisplayName ? (
          <span className="workspace-chip">{notebook.kernelDisplayName}</span>
        ) : null}
      </div>

      {notebook.cells.length === 0 ? (
        <div className="workspace-editor-empty">
          <div>
            <h3>No cells found</h3>
            <p>This notebook has no editable cells yet.</p>
          </div>
        </div>
      ) : (
        <div className="workspace-notebook-cells">
          {notebook.cells.map((cell) => (
            <article key={cell.id} className="workspace-notebook-cell">
              <div className="workspace-notebook-cell-head">
                <div>
                  <span className="workspace-pane-eyebrow">
                    {humanizeCellType(cell.cellType)} cell
                  </span>
                  <h3>
                    {cell.index + 1}. {cell.id}
                  </h3>
                </div>
                <div className="workspace-pane-meta">
                  <span className="workspace-chip">{cell.outputCount} outputs</span>
                  {cell.executionCount !== null ? (
                    <span className="workspace-chip">
                      exec {cell.executionCount}
                    </span>
                  ) : null}
                  {cell.metadataEntryCount > 0 ? (
                    <span className="workspace-chip">
                      metadata {cell.metadataEntryCount}
                    </span>
                  ) : null}
                </div>
              </div>

              <textarea
                className={`workspace-notebook-editor ${
                  cell.cellType === "markdown" ? "is-markdown" : ""
                }`}
                value={cell.source}
                readOnly={document.readOnly || document.saving}
                spellCheck={cell.cellType === "markdown"}
                onChange={(event) => {
                  const nextContent = updateWorkspaceNotebookCellSource(
                    document.content,
                    cell.id,
                    event.target.value,
                  );
                  if (nextContent === null) {
                    return;
                  }
                  onChangeFileContent(document.path, nextContent);
                }}
              />

              {cell.outputPreview.length > 0 ? (
                <div className="workspace-notebook-output">
                  <span className="workspace-pane-eyebrow">Output preview</span>
                  {cell.outputPreview.map((preview, index) => (
                    <pre key={`${cell.id}:${index}`}>{preview}</pre>
                  ))}
                </div>
              ) : null}

              {onAttachSelection ? (
                <div className="workspace-pane-meta">
                  <button
                    type="button"
                    className="workspace-pane-button"
                    onClick={() =>
                      onAttachSelection({
                        path: `${document.path}#${cell.id}`,
                        selection: cell.source,
                      })
                    }
                    disabled={!cell.source.trim()}
                  >
                    Send Cell
                  </button>
                </div>
              ) : null}
            </article>
          ))}
        </div>
      )}
    </div>
  );
}
