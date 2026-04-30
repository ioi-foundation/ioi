import type { AgentWorkbenchRuntime } from "../runtime/agent-runtime";
import type { ProjectFile } from "../types/graph";

export interface WorkflowComposerProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

export interface WorkflowComposerProps {
  runtime: AgentWorkbenchRuntime;
  currentProject?: WorkflowComposerProjectScope;
  initialFile?: ProjectFile | null;
  onInitialFileLoaded?: () => void;
}
