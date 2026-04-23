import type { ArtifactHubNavigation } from "./artifactHubNavigation";
import {
  ackPendingChatShellLaunchRequest,
  peekPendingChatShellLaunchRequest,
} from "./chatShellLaunchState";

export function applyPendingChatShellLaunch(
  hubNavigation: ArtifactHubNavigation,
  appliedLaunchIds: Set<string>,
) {
  let cancelled = false;

  const applyLaunch = async () => {
    const pendingLaunch = await peekPendingChatShellLaunchRequest();
    if (!pendingLaunch || cancelled) {
      return;
    }

    const { launchId, request } = pendingLaunch;
    if (appliedLaunchIds.has(launchId)) {
      return;
    }

    const claimed = await ackPendingChatShellLaunchRequest(launchId);
    if (!claimed || cancelled) {
      return;
    }

    appliedLaunchIds.add(launchId);

    switch (request.kind) {
      case "artifact":
        await hubNavigation.openArtifact(request.artifactId);
        return;
      case "view":
        await hubNavigation.openView(request.view, request.turnId ?? null);
        return;
      default:
        return;
    }
  };

  void applyLaunch();
  const retryHandle = window.setTimeout(() => {
    void applyLaunch();
  }, 250);

  return () => {
    cancelled = true;
    window.clearTimeout(retryHandle);
  };
}
