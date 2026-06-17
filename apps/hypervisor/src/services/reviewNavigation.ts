import {
  openChatAssistantWorkbench,
  openChatCapabilities,
  openChatConnectorPolicy,
  openChatEvidenceSession,
  openChatPolicyView,
  openChatSettings,
  type ChatAssistantWorkbenchSession,
} from "./chatShellNavigation";
import { openArtifactTarget } from "./artifactNavigation";

export async function openArtifactReviewTarget(artifactId: string) {
  await openArtifactTarget(artifactId);
}

export async function openEvidenceReviewSession(sessionId: string) {
  await openChatEvidenceSession(sessionId);
}

export async function openAssistantWorkbenchReview(
  session: ChatAssistantWorkbenchSession,
) {
  await openChatAssistantWorkbench(session);
}

export async function openReviewCapabilities() {
  await openChatCapabilities();
}

export async function openReviewPolicyCenter() {
  await openChatPolicyView();
}

export async function openReviewConnectorPolicy(
  connectorId?: string | null,
) {
  await openChatConnectorPolicy(connectorId);
}

export async function openReviewSettings() {
  await openChatSettings();
}
