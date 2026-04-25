import test from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";

import { diffArtifactFiles } from "./artifact-files";

test("diffArtifactFiles ignores revision metadata when requested", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "chat-artifact-files-"));
  const baseDir = path.join(root, "base");
  const restoredDir = path.join(root, "restored");
  try {
    await mkdir(baseDir, { recursive: true });
    await mkdir(restoredDir, { recursive: true });

    await Promise.all([
      writeFile(path.join(baseDir, "artifact-manifest.json"), "{\"title\":\"Artifact\"}"),
      writeFile(path.join(restoredDir, "artifact-manifest.json"), "{\"title\":\"Artifact\"}"),
      writeFile(path.join(baseDir, "index.html"), "<!doctype html><main>base</main>"),
      writeFile(path.join(restoredDir, "index.html"), "<!doctype html><main>base</main>"),
      writeFile(path.join(baseDir, "generation.json"), "{\"revision\":\"base\"}"),
      writeFile(path.join(restoredDir, "generation.json"), "{\"revision\":\"restored\"}"),
      writeFile(path.join(baseDir, "chat-artifact-session.json"), "{\"activeRevisionId\":\"base\"}"),
      writeFile(
        path.join(restoredDir, "chat-artifact-session.json"),
        "{\"activeRevisionId\":\"restored\"}",
      ),
      writeFile(path.join(baseDir, "revision-history.json"), "[\"base\"]"),
      writeFile(path.join(restoredDir, "revision-history.json"), "[\"base\",\"restored\"]"),
    ]);

    assert.deepEqual(
      await diffArtifactFiles(baseDir, restoredDir),
      ["revision-history.json", "chat-artifact-session.json"],
    );
    assert.deepEqual(
      await diffArtifactFiles(baseDir, restoredDir, {
        ignorePaths: ["chat-artifact-session.json", "revision-history.json"],
      }),
      [],
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
