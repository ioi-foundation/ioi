import { WorkflowNodeBindingSections } from "./WorkflowNodeBindingEditor/sections";
import type { WorkflowNodeBindingEditorProps } from "./WorkflowNodeBindingEditor/types";

export function WorkflowNodeBindingEditor({
  node,
  logic,
  law,
  sectionStatus,
  sectionDetail,
  modelAttachmentCounts,
  dryRunView,
  onUpdate,
  updateLogic,
  onDryRun,
}: WorkflowNodeBindingEditorProps) {
  return (
    <section
      className="workflow-config-section-block"
      data-config-section="bindings"
      data-testid="workflow-config-section-bindings"
      tabIndex={-1}
    >
      <header>
        <div>
          <h4>Bindings</h4>
          <p>Runtime-specific settings for this primitive.</p>
        </div>
        <span data-section-status={sectionStatus}>{sectionDetail}</span>
      </header>
      <WorkflowNodeBindingSections
        node={node}
        logic={logic}
        law={law}
        modelAttachmentCounts={modelAttachmentCounts}
        dryRunView={dryRunView}
        onUpdate={onUpdate}
        updateLogic={updateLogic}
        onDryRun={onDryRun}
      />
    </section>
  );
}
