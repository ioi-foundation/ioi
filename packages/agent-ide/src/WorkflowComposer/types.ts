import type { AgentWorkbenchRuntime } from "../runtime/agent-runtime";
import type { ProjectFile } from "../types/graph";

export interface WorkflowComposerProjectScope {
  id: string;
  name: string;
  description: string;
  environment: string;
  rootPath: string;
}

export interface WorkflowComposerPreflightSeed {
  panel: "readiness";
  capabilityRef?: string | null;
  nodeId?: string | null;
  actionKind?: string | null;
  source?: "authority-center" | "settings-authority" | "workflow" | string;
}

export interface WorkflowComposerProps {
  runtime: AgentWorkbenchRuntime;
  currentProject?: WorkflowComposerProjectScope;
  initialFile?: ProjectFile | null;
  onInitialFileLoaded?: () => void;
  preflightSeed?: WorkflowComposerPreflightSeed | null;
  onPreflightSeedConsumed?: () => void;
}
