import type { ArtifactHubViewKey } from "../types";
import { showChatShellWithLaunchRequest } from "./chatShellLaunchState";

type OpenArtifactHub = (
  view: ArtifactHubViewKey,
  turnId?: string | null,
) => Promise<void>;

type OpenArtifactById = (artifactId: string) => Promise<void>;

export async function openArtifactTarget(artifactId: string) {
  await showChatShellWithLaunchRequest({
    kind: "artifact",
    artifactId,
  });
}

export async function openArtifactHubView(
  view?: ArtifactHubViewKey,
  turnId?: string | null,
) {
  await showChatShellWithLaunchRequest({
    kind: "view",
    view: view ?? "kernel_logs",
    turnId,
  });
}

export async function openArtifactView(
  openArtifactHub: OpenArtifactHub,
  view?: ArtifactHubViewKey,
  turnId?: string | null,
) {
  await openArtifactHub(view ?? "kernel_logs", turnId);
}

export async function openArtifactById(
  openArtifactByIdImpl: OpenArtifactById,
  artifactId: string,
) {
  await openArtifactByIdImpl(artifactId);
}

export async function openValidationEvidence(params: {
  preferredEvidenceArtifactId?: string | null;
  openArtifactHub: OpenArtifactHub;
  openArtifactById: OpenArtifactById;
}) {
  const { preferredEvidenceArtifactId, openArtifactHub, openArtifactById } = params;
  if (preferredEvidenceArtifactId) {
    await openArtifactById(preferredEvidenceArtifactId);
    return;
  }

  await openArtifactHub("kernel_logs");
}

export async function openSourceSummary(openArtifactHub: OpenArtifactHub) {
  await openArtifactHub("sources");
}
