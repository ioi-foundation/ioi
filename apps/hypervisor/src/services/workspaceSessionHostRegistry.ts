import {
  type WorkspaceSessionHost,
} from "./workspaceSessionHost";
import { substratePreviewWorkspaceSessionHost } from "./workspaceSubstratePreviewHost";

export function getDefaultWorkspaceSessionHost(): WorkspaceSessionHost {
  const requestedHost = (
    import.meta.env.VITE_HYPERVISOR_WORKSPACE_HOST ?? ""
  ).trim().toLowerCase();
  if (["substrate", "substrate-preview", "direct-react"].includes(requestedHost)) {
    return substratePreviewWorkspaceSessionHost;
  }
  return substratePreviewWorkspaceSessionHost;
}

export { substratePreviewWorkspaceSessionHost };
