import { ReactFlowProvider } from "@xyflow/react";
import { WorkflowComposerContent } from "./WorkflowComposer/content";
import type { WorkflowComposerProps } from "./WorkflowComposer/types";
import "./WorkflowComposer.css";
import "./styles/theme.css";

export type { WorkflowComposerProjectScope, WorkflowComposerProps } from "./WorkflowComposer/types";

export function WorkflowComposer(props: WorkflowComposerProps) {
  return (
    <ReactFlowProvider>
      <WorkflowComposerContent {...props} />
    </ReactFlowProvider>
  );
}
