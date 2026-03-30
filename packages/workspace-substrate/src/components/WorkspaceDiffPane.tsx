import type { WorkspaceDiffDocument } from "../types";

interface WorkspaceDiffPaneProps {
  diff: WorkspaceDiffDocument;
}

export function WorkspaceDiffPane({ diff }: WorkspaceDiffPaneProps) {
  return (
    <div className="workspace-document-meta">
      <span className="workspace-chip">{diff.path}</span>
      <span className="workspace-chip">{diff.originalLabel}</span>
      <span className="workspace-chip">{diff.modifiedLabel}</span>
    </div>
  );
}
