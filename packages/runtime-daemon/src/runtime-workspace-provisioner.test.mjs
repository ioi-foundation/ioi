import assert from "node:assert/strict";
import { existsSync, statSync } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  provisionSessionWorkspace,
  disposeSessionWorkspace,
  deriveWorkspaceInitializer,
} from "./runtime-workspace-provisioner.mjs";

async function withSessionsRoot(run) {
  const sessionsRoot = await fs.mkdtemp(
    path.join(os.tmpdir(), "ioi-provisioner-test-"),
  );
  try {
    await run(sessionsRoot);
  } finally {
    await fs.rm(sessionsRoot, { recursive: true, force: true });
  }
}

test("provisions a real isolated scratch workspace on disk", async () => {
  await withSessionsRoot(async (sessionsRoot) => {
    const result = await provisionSessionWorkspace(
      {
        initializer: deriveWorkspaceInitializer({
          workspaceMountPolicy: "public_trunk",
        }),
        sessionRef: "session-route:demo",
      },
      { sessionsRoot },
    );
    assert.equal(result.provisioned, true);
    // Real directory, isolated under the sessions root (not the repo / cwd).
    assert.ok(existsSync(result.workspace_root), "workspace dir exists");
    assert.ok(statSync(result.workspace_root).isDirectory());
    assert.ok(
      path
        .normalize(result.workspace_root)
        .startsWith(path.normalize(sessionsRoot) + path.sep),
      "workspace is under the sessions root",
    );
    assert.match(result.workspace_artifact_ref, /^agentgres:\/\/artifact\/workspace\//);
    assert.equal(result.custody_posture, "public_trunk");
    assert.equal(result.components.provisioner, "ready");
    assert.equal(result.components.workspace_content, "ready");
  });
});

test("two sessions get distinct isolated workspaces", async () => {
  await withSessionsRoot(async (sessionsRoot) => {
    const a = await provisionSessionWorkspace(
      { sessionRef: "session-a" },
      { sessionsRoot },
    );
    const b = await provisionSessionWorkspace(
      { sessionRef: "session-b" },
      { sessionsRoot },
    );
    assert.notEqual(a.workspace_root, b.workspace_root);
  });
});

test("realizes a git spec via the injected git runner", async () => {
  await withSessionsRoot(async (sessionsRoot) => {
    const cloneCalls = [];
    const result = await provisionSessionWorkspace(
      {
        initializer: deriveWorkspaceInitializer({
          gitSpec: { remote_uri: "https://example.com/repo.git" },
          workspaceMountPolicy: "public_trunk",
        }),
        sessionRef: "session-git",
      },
      {
        sessionsRoot,
        runGit: async (args, opts) => {
          cloneCalls.push({ args, opts });
        },
      },
    );
    assert.equal(cloneCalls.length, 1);
    assert.equal(cloneCalls[0].args[0], "clone");
    assert.ok(cloneCalls[0].args.includes("--depth"));
    assert.equal(result.realized_specs[0].realized, true);
    assert.equal(result.components.workspace_content, "ready");
  });
});

test("defers a git spec (no fake clone) when no git runner is available", async () => {
  await withSessionsRoot(async (sessionsRoot) => {
    const result = await provisionSessionWorkspace(
      {
        initializer: deriveWorkspaceInitializer({
          gitSpec: { remote_uri: "https://example.com/repo.git" },
        }),
      },
      { sessionsRoot },
    );
    assert.equal(result.realized_specs[0].realized, false);
    assert.equal(result.components.workspace_content, "initializing");
  });
});

test("dispose only removes paths under the sessions root", async () => {
  await withSessionsRoot(async (sessionsRoot) => {
    const result = await provisionSessionWorkspace(
      { sessionRef: "session-dispose" },
      { sessionsRoot },
    );
    assert.ok(existsSync(result.workspace_root));
    const removed = await disposeSessionWorkspace(result.workspace_root, {
      sessionsRoot,
    });
    assert.equal(removed, true);
    assert.equal(existsSync(result.workspace_root), false);

    // Refuses to remove a path outside the sessions root.
    const outside = await disposeSessionWorkspace("/etc", { sessionsRoot });
    assert.equal(outside, false);
  });
});
