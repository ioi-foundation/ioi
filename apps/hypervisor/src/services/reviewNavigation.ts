import type { AssistantWorkbenchSession } from "@ioi/hypervisor-workbench";
import { showHypervisorWithLaunchRequest } from "./hypervisorLaunchState";

function openHypervisorSurface(path: string) {
  window.location.assign(path);
}

export async function openArtifactReviewTarget(artifactId: string) {
  await showHypervisorWithLaunchRequest({
    kind: "artifact",
    artifactId,
  });
  openHypervisorSurface("/receipts");
}

export async function openEvidenceReviewSession(sessionId: string) {
  await showHypervisorWithLaunchRequest({
    kind: "session-target",
    sessionId,
  });
  openHypervisorSurface("/sessions");
}

export async function openAssistantWorkbenchReview(
  session: AssistantWorkbenchSession,
) {
  await showHypervisorWithLaunchRequest({
    kind: "assistant-workbench",
    session,
  });
  openHypervisorSurface("/missions");
}

export async function openReviewCapabilities() {
  openHypervisorSurface("/agents");
}

export async function openReviewPolicyCenter() {
  openHypervisorSurface("/authority");
}

export async function openReviewConnectorPolicy(
  connectorId?: string | null,
) {
  await showHypervisorWithLaunchRequest({
    kind: "policy",
    connectorId: connectorId ?? null,
  });
  openHypervisorSurface("/authority");
}

export async function openReviewSettings() {
  openHypervisorSurface("/settings");
}
