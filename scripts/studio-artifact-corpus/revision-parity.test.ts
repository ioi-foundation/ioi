import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";

import { restoredMatchesRevisionSource } from "./revision-parity";
import type { CaseSummary, GeneratedArtifactEvidence } from "./types";

function manifestWithPath(filePath: string): GeneratedArtifactEvidence["manifest"] {
  return {
    artifactId: `artifact-${filePath}`,
    title: "Artifact",
    renderer: "html_iframe",
    artifactClass: "interactive_single_file",
    primaryTab: "render",
    verification: {
      status: "ready",
      lifecycleState: "ready",
      failure: null,
    },
    files: [
      {
        path: filePath,
        mime: "text/html",
        role: "primary",
        renderable: true,
        downloadable: false,
        externalUrl: null,
      },
    ],
  };
}

test("restoredMatchesRevisionSource trusts saved revision lineage when standalone base diverges", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "studio-revision-parity-"));
  const baseDir = path.join(root, "base");
  const refinedDir = path.join(root, "refined");
  const restoreDir = path.join(root, "restore");
  try {
    await Promise.all([
      mkdir(baseDir, { recursive: true }),
      mkdir(refinedDir, { recursive: true }),
      mkdir(restoreDir, { recursive: true }),
    ]);

    await Promise.all([
      writeFile(path.join(baseDir, "artifact-manifest.json"), "{\"title\":\"Base\"}"),
      writeFile(path.join(baseDir, "explore-dog-shampoo-rollout.html"), "<main>rerun base</main>"),
      writeFile(path.join(refinedDir, "revision-history.json"), JSON.stringify([
        {
          revisionId: "base-revision",
          artifactManifest: manifestWithPath("index.html"),
        },
      ])),
      writeFile(path.join(restoreDir, "artifact-manifest.json"), "{\"title\":\"Restore\"}"),
    ]);

    const baseCase = {
      artifactDir: baseDir,
      manifest: manifestWithPath("explore-dog-shampoo-rollout.html"),
    } as CaseSummary;
    const restoreEvidence = {
      activeRevisionId: "base-revision",
      manifest: manifestWithPath("index.html"),
    } as GeneratedArtifactEvidence;

    assert.equal(
      await restoredMatchesRevisionSource(
        baseCase,
        refinedDir,
        "base-revision",
        restoreDir,
        restoreEvidence,
        ["studio-session.json", "revision-history.json"],
      ),
      true,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
