import type { WorkflowComposerProps } from "./types";
import { useWorkflowComposerController } from "./controller";
import { WorkflowComposerView } from "./view";

export function WorkflowComposerContent(props: WorkflowComposerProps) {
  const model = useWorkflowComposerController(props);
  return <WorkflowComposerView {...model} />;
}
