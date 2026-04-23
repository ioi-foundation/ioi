import type { ArtifactHubViewKey, SourceSummary } from "../types";
import {
  openArtifactById as openArtifactByIdTarget,
  openArtifactView,
  openSourceSummary,
  openValidationEvidence,
} from "./artifactNavigation";

export type ArtifactHubOpenView = (
  view: ArtifactHubViewKey,
  turnId?: string | null,
) => Promise<void>;

export type ArtifactHubOpenArtifactById = (
  artifactId: string,
) => Promise<void>;

export type ArtifactHubNavigation = {
  openSourceSummary(summary: SourceSummary): Promise<void>;
  openValidationEvidence(): Promise<void>;
  openView(view?: ArtifactHubViewKey, turnId?: string | null): Promise<void>;
  openArtifact(artifactId: string): Promise<void>;
};

export function buildArtifactHubNavigation(params: {
  openArtifactHub: ArtifactHubOpenView;
  openArtifactById: ArtifactHubOpenArtifactById;
  preferredEvidenceArtifactId?: string | null;
}): ArtifactHubNavigation {
  const { openArtifactHub, openArtifactById, preferredEvidenceArtifactId } = params;

  return {
    async openSourceSummary(_summary: SourceSummary) {
      await openSourceSummary(openArtifactHub);
    },
    async openValidationEvidence() {
      await openValidationEvidence({
        preferredEvidenceArtifactId,
        openArtifactById,
        openArtifactHub,
      });
    },
    async openView(view?: ArtifactHubViewKey, turnId?: string | null) {
      await openArtifactView(openArtifactHub, view, turnId);
    },
    async openArtifact(artifactId: string) {
      await openArtifactByIdTarget(openArtifactById, artifactId);
    },
  };
}
