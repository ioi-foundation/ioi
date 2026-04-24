import {
  type WorkspaceWorkbenchHost,
} from "./workspaceWorkbenchHost";
import {
  directWorkspaceWorkbenchHost,
  substratePreviewWorkspaceWorkbenchHost,
} from "./directWorkspaceWorkbenchHost";
import { openVsCodeWorkbenchHost } from "./openVsCodeWorkbenchHost";

export function getDefaultWorkspaceWorkbenchHost(): WorkspaceWorkbenchHost {
  const requestedHost = (
    import.meta.env.VITE_AUTOPILOT_WORKSPACE_HOST ?? ""
  ).trim().toLowerCase();
  if (requestedHost === "openvscode" || requestedHost === "iframe") {
    return openVsCodeWorkbenchHost;
  }
  if (
    requestedHost === "substrate" ||
    requestedHost === "substrate-preview" ||
    requestedHost === "direct-react"
  ) {
    return substratePreviewWorkspaceWorkbenchHost;
  }
  return directWorkspaceWorkbenchHost;
}

export { directWorkspaceWorkbenchHost };
export { substratePreviewWorkspaceWorkbenchHost };
export { openVsCodeWorkbenchHost };
