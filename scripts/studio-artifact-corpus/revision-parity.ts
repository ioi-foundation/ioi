import path from "node:path";

import { diffArtifactFiles, readJsonIfPresent } from "./artifact-files";
import type { CaseSummary, GeneratedArtifactEvidence } from "./types";

export type RevisionHistoryEntry = {
  revisionId: string;
  artifactManifest: GeneratedArtifactEvidence["manifest"];
};

export function normalizeManifestForRevisionParity(
  manifest: GeneratedArtifactEvidence["manifest"],
) {
  return {
    title: manifest.title,
    renderer: manifest.renderer,
    artifactClass: manifest.artifactClass,
    primaryTab: manifest.primaryTab,
    verification: {
      status: manifest.verification?.status ?? null,
      lifecycleState: manifest.verification?.lifecycleState ?? null,
      failure: manifest.verification?.failure ?? null,
    },
    files: [...manifest.files]
      .map((file) => ({
        path: file.path,
        mime: file.mime,
        role: file.role,
        renderable: file.renderable,
        downloadable: file.downloadable,
        externalUrl: file.externalUrl ?? null,
      }))
      .sort((left, right) => left.path.localeCompare(right.path)),
  };
}

export function manifestsMatchForRevisionParity(
  left: GeneratedArtifactEvidence["manifest"],
  right: GeneratedArtifactEvidence["manifest"],
) {
  return (
    JSON.stringify(normalizeManifestForRevisionParity(left)) ===
    JSON.stringify(normalizeManifestForRevisionParity(right))
  );
}

export async function restoredMatchesRevisionSource(
  base: CaseSummary,
  refinedArtifactDir: string,
  baseRevisionId: string,
  restoreArtifactDir: string,
  restoreEvidence: GeneratedArtifactEvidence,
  ignorePaths: string[],
) {
  const revisionHistory =
    (await readJsonIfPresent<RevisionHistoryEntry[]>(
      path.join(refinedArtifactDir, "revision-history.json"),
    )) ?? [];
  const baseRevision = revisionHistory.find(
    (revision) => revision.revisionId === baseRevisionId,
  );
  if (!baseRevision) {
    return (
      (
        await diffArtifactFiles(base.artifactDir, restoreArtifactDir, {
          ignorePaths,
        })
      ).length === 0
    );
  }

  if (manifestsMatchForRevisionParity(base.manifest, baseRevision.artifactManifest)) {
    return (
      (
        await diffArtifactFiles(base.artifactDir, restoreArtifactDir, {
          ignorePaths,
        })
      ).length === 0
    );
  }

  return (
    restoreEvidence.activeRevisionId === baseRevisionId &&
    manifestsMatchForRevisionParity(
      restoreEvidence.manifest,
      baseRevision.artifactManifest,
    )
  );
}
