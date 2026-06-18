import {
  type WorkspaceWorkbenchHost,
} from "./workspaceWorkbenchHost";
import { substratePreviewWorkspaceWorkbenchHost } from "./workspaceSubstratePreviewHost";

export function getDefaultWorkspaceWorkbenchHost(): WorkspaceWorkbenchHost {
  const requestedHost = (
    import.meta.env.VITE_HYPERVISOR_WORKSPACE_HOST ?? ""
  ).trim().toLowerCase();
  if (["substrate", "substrate-preview", "direct-react"].includes(requestedHost)) {
    return substratePreviewWorkspaceWorkbenchHost;
  }
  return substratePreviewWorkspaceWorkbenchHost;
}

export { substratePreviewWorkspaceWorkbenchHost };
