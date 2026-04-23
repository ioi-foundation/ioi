import type { WorkspaceActionContext } from "./workspaceActionContext";

export type WorkspaceBridgeRouteRequest = {
  requestId: string;
  requestType: string;
  context?: WorkspaceActionContext | Record<string, unknown> | null;
  payload: Record<string, unknown>;
  timestampMs: number;
};
