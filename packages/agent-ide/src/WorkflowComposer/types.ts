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

export interface WorkflowProjectMaterializationRequest {
  workflowId: string;
  workflowName: string;
  workflowPath: string;
  projectRoot: string;
  projectName: string;
  dryRun: boolean;
  workflowSnapshot: unknown;
  testsSnapshot: unknown;
  requestedAtMs: number;
}

export interface WorkflowProjectMaterializationResult {
  receiptId: string;
  status: "proposed" | "materialized" | "opened" | "blocked";
  rootPath: string;
  manifestPath: string;
  workflowPath: string;
  evalPath: string;
  expectedReceiptsPath: string;
  openedInWorkspace: boolean;
  blockers: string[];
}

export interface WorkflowProjectMaterializationState {
  status: "idle" | "running" | "done" | "blocked";
  message: string | null;
  result?: WorkflowProjectMaterializationResult | null;
}

export interface WorkflowComposerProps {
  runtime: AgentWorkbenchRuntime;
  currentProject?: WorkflowComposerProjectScope;
  initialFile?: ProjectFile | null;
  onInitialFileLoaded?: () => void;
  preflightSeed?: WorkflowComposerPreflightSeed | null;
  onPreflightSeedConsumed?: () => void;
  onMaterializeProject?: (
    request: WorkflowProjectMaterializationRequest,
  ) => Promise<WorkflowProjectMaterializationResult> | WorkflowProjectMaterializationResult;
}
