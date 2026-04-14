import type { AgentRuntime, AgentSessionRuntime } from "@ioi/agent-ide";
import {
  getSessionRuntime as getSharedSessionRuntime,
  setDefaultSessionRuntime,
  setSessionRuntime,
} from "@ioi/agent-ide";
import type { LocalEngineSnapshot } from "../types";
import { TauriRuntime, type WorkspaceWorkflowSummary } from "./TauriRuntime";

export interface SessionOperatorRuntime extends AgentSessionRuntime {
  getLocalEngineSnapshot(): Promise<LocalEngineSnapshot>;
  stageLocalEngineOperation(input: {
    subjectKind: string;
    operation: string;
    sourceUri?: string | null;
    subjectId?: string | null;
    notes?: string | null;
  }): Promise<void>;
  retryLocalEngineParentPlaybookRun(runId: string): Promise<void>;
  resumeLocalEngineParentPlaybookRun(
    runId: string,
    stepId?: string | null,
  ): Promise<void>;
  dismissLocalEngineParentPlaybookRun(runId: string): Promise<void>;
  removeLocalEngineOperation(operationId: string): Promise<void>;
  promoteLocalEngineOperation(operationId: string): Promise<void>;
}

export type SessionWorkbenchRuntime = AgentRuntime &
  AgentSessionRuntime & {
    listWorkspaceWorkflows?: () => Promise<WorkspaceWorkflowSummary[]>;
  };

const defaultSessionRuntime = new TauriRuntime();
setDefaultSessionRuntime(defaultSessionRuntime);

function isSessionOperatorRuntime(
  runtime: AgentSessionRuntime,
): runtime is SessionOperatorRuntime {
  const candidate = runtime as Partial<SessionOperatorRuntime>;
  return (
    typeof candidate.getLocalEngineSnapshot === "function" &&
    typeof candidate.stageLocalEngineOperation === "function" &&
    typeof candidate.retryLocalEngineParentPlaybookRun === "function" &&
    typeof candidate.resumeLocalEngineParentPlaybookRun === "function" &&
    typeof candidate.dismissLocalEngineParentPlaybookRun === "function" &&
    typeof candidate.removeLocalEngineOperation === "function" &&
    typeof candidate.promoteLocalEngineOperation === "function"
  );
}

function isSessionWorkbenchRuntime(
  runtime: AgentSessionRuntime,
): runtime is SessionWorkbenchRuntime {
  const candidate = runtime as Partial<SessionWorkbenchRuntime>;
  return (
    typeof candidate.runGraph === "function" &&
    typeof candidate.stopExecution === "function" &&
    typeof candidate.getAvailableTools === "function" &&
    typeof candidate.runNode === "function" &&
    typeof candidate.loadProject === "function" &&
    typeof candidate.saveProject === "function" &&
    typeof candidate.getAgents === "function" &&
    typeof candidate.getFleetState === "function" &&
    typeof candidate.getRuntimeCatalogEntries === "function" &&
    typeof candidate.stageRuntimeCatalogEntry === "function" &&
    typeof candidate.onEvent === "function"
  );
}

export function getSessionRuntime(): AgentSessionRuntime {
  return getSharedSessionRuntime();
}

export function getSessionWorkbenchRuntime(): SessionWorkbenchRuntime {
  const runtime = getSharedSessionRuntime();
  if (isSessionWorkbenchRuntime(runtime)) {
    return runtime;
  }
  return defaultSessionRuntime;
}

export function getSessionOperatorRuntime(): SessionOperatorRuntime {
  const runtime = getSharedSessionRuntime();
  if (isSessionOperatorRuntime(runtime)) {
    return runtime;
  }
  return defaultSessionRuntime;
}

export { setSessionRuntime };
