import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { computeWorkspaceDiffProjection } from "./runtime-workspace-diff-projection.mjs";

const execFileAsync = promisify(execFile);

async function withWorkspace(run) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "ioi-diff-test-"));
  try {
    await run(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

test("projects a fresh scratch workspace as real added files (filesystem walk)", async () => {
  await withWorkspace(async (dir) => {
    await fs.writeFile(
      path.join(dir, "index.html"),
      "<!doctype html><h1>PQC</h1>\n",
    );
    await fs.mkdir(path.join(dir, "assets"));
    await fs.writeFile(path.join(dir, "assets", "styles.css"), "body{}\n");

    const projection = await computeWorkspaceDiffProjection({ workspaceRoot: dir });
    assert.equal(projection.source, "filesystem");
    assert.equal(projection.changed_file_count, 2);
    const names = projection.changed_file_groups
      .flatMap((group) => group.files.map((file) => file.name))
      .sort();
    assert.deepEqual(names, ["index.html", "styles.css"]);
    const indexFile = projection.changed_file_groups
      .flatMap((group) => group.files)
      .find((file) => file.name === "index.html");
    assert.equal(indexFile.status, "added");
    assert.match(indexFile.delta, /^\+\d+$/);
  });
});

test("projects a git work tree as real git status deltas", async () => {
  await withWorkspace(async (dir) => {
    await execFileAsync("git", ["init", "-q"], { cwd: dir });
    await execFileAsync("git", ["config", "user.email", "t@t.test"], { cwd: dir });
    await execFileAsync("git", ["config", "user.name", "t"], { cwd: dir });
    await fs.writeFile(path.join(dir, "README.md"), "base\n");
    await execFileAsync("git", ["add", "-A"], { cwd: dir });
    await execFileAsync("git", ["commit", "-qm", "base"], { cwd: dir });
    // Now produce a real change.
    await fs.writeFile(path.join(dir, "index.html"), "<h1>PQC</h1>\n");

    const projection = await computeWorkspaceDiffProjection({ workspaceRoot: dir });
    assert.equal(projection.source, "git");
    const names = projection.changed_file_groups
      .flatMap((group) => group.files.map((file) => file.name))
      .sort();
    assert.ok(names.includes("index.html"));
  });
});

test("returns an empty projection for a missing workspace root", async () => {
  const projection = await computeWorkspaceDiffProjection({ workspaceRoot: "" });
  assert.equal(projection.source, "absent");
  assert.deepEqual(projection.changed_file_groups, []);
});
