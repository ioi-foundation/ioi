import type { ConnectorWorkbenchRuntime } from "./connector-runtime-types";
import type { GraphExecutionRuntime } from "./graph-runtime-types";
import type { WorkbenchOperationsRuntime } from "./operations-runtime-types";

export interface AgentWorkbenchRuntime
  extends GraphExecutionRuntime,
    WorkbenchOperationsRuntime,
    ConnectorWorkbenchRuntime {}

export type AgentRuntime = AgentWorkbenchRuntime;
