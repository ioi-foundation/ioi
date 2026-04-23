import {
  type WorkspaceWorkbenchHost,
} from "./workspaceWorkbenchHost";
import { directWorkspaceWorkbenchHost } from "./directWorkspaceWorkbenchHost";
import { openVsCodeWorkbenchHost } from "./openVsCodeWorkbenchHost";

export function getDefaultWorkspaceWorkbenchHost(): WorkspaceWorkbenchHost {
  const requestedHost = (
    import.meta.env.VITE_AUTOPILOT_WORKSPACE_HOST ?? ""
  ).trim().toLowerCase();
  if (requestedHost === "openvscode" || requestedHost === "iframe") {
    return openVsCodeWorkbenchHost;
  }
  return directWorkspaceWorkbenchHost;
}

export { directWorkspaceWorkbenchHost };
export { openVsCodeWorkbenchHost };
