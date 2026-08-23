import assert from "node:assert/strict";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";

import { captureCertifiedDaemonSourceBasis } from "./certified-daemon-source-basis.mjs";

const command = (cwd, executable, args) => {
  const result = spawnSync(executable, args, { cwd, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
};

const fixture = () => {
  const repo = mkdtempSync(path.join(tmpdir(), "ioi-certified-source-"));
  command(repo, "git", ["init", "-q"]);
  command(repo, "git", ["config", "user.email", "fixture@ioi.local"]);
  command(repo, "git", ["config", "user.name", "IOI Fixture"]);
  writeFileSync(path.join(repo, ".gitignore"), "/target/\n");
  writeFileSync(path.join(repo, "tracked.txt"), "committed\n");
  command(repo, "git", ["add", ".gitignore", "tracked.txt"]);
  command(repo, "git", ["commit", "-qm", "fixture"]);
  const binary = path.join(repo, "target/debug/hypervisor-daemon");
  mkdirSync(path.dirname(binary), { recursive: true });
  writeFileSync(binary, "fixture-daemon\n");
  chmodSync(binary, 0o700);
  return { repo, binary };
};

test("captures a committed tree and fingerprints the one explicit non-build exclusion", () => {
  const { repo, binary } = fixture();
  writeFileSync(path.join(repo, "0"), "");
  const basis = captureCertifiedDaemonSourceBasis({ repo, binaryPath: binary, build: false });
  assert.match(basis.source_commit, /^[0-9a-f]{40}$/u);
  assert.match(basis.source_tree, /^[0-9a-f]{40}$/u);
  assert.equal(basis.source_dirty_state, "clean");
  assert.deepEqual(basis.excluded_untracked.map((entry) => entry.path), ["0"]);
  assert.equal(basis.excluded_untracked[0].size_bytes, 0);
  assert.match(basis.daemon_binary_sha256, /^sha256:[0-9a-f]{64}$/u);
});

test("refuses tracked mutations and unexpected untracked paths", () => {
  const tracked = fixture();
  writeFileSync(path.join(tracked.repo, "tracked.txt"), "changed\n");
  assert.throws(
    () => captureCertifiedDaemonSourceBasis({ repo: tracked.repo, binaryPath: tracked.binary, build: false }),
    /tracked or index mutations/u,
  );

  const untracked = fixture();
  writeFileSync(path.join(untracked.repo, "surprise.txt"), "not admitted\n");
  assert.throws(
    () => captureCertifiedDaemonSourceBasis({ repo: untracked.repo, binaryPath: untracked.binary, build: false }),
    /unexpected untracked paths/u,
  );
});
