import type { WorkflowFileBundleModel } from "../../../runtime/workflow-file-bundle-model";

type WorkflowFilesPanelProps = {
  model: WorkflowFileBundleModel;
};

export function WorkflowFilesPanel({ model }: WorkflowFilesPanelProps) {
  return (
    <>
      <h3>Files</h3>
      <p>
        Git-backed bundle surfaces stay separate from run state and local UI
        state.
      </p>
      <div
        className="workflow-rail-list"
        data-testid="workflow-files-list"
        data-ready-count={model.readyItems}
        data-pending-count={model.pendingItems}
        data-workflow-path={model.workflowPath}
      >
        {model.items.map((item) => (
          <article
            key={item.id}
            className="workflow-file-row"
            data-testid={`workflow-file-${item.id}`}
            data-file-ready={String(item.ready)}
            data-file-exported={String(item.exported)}
          >
            <strong>{item.label}</strong>
            <code>{item.path}</code>
            <span>{item.status}</span>
          </article>
        ))}
      </div>
    </>
  );
}
