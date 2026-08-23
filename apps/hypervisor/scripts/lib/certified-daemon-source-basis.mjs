import crypto from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const sha256 = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;

const run = (command, args, cwd, options = {}) => {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = String(result.stderr || result.stdout || "").trim().split("\n").at(-1) || `exit ${result.status}`;
    throw new Error(`certified source basis command failed: ${command} ${args.join(" ")}: ${detail}`);
  }
  return String(result.stdout || "").trim();
};

/**
 * Build and identify the exact daemon used by a certified campaign.
 *
 * The repository has one owner-retained, unrelated empty file named `0`. It is
 * explicitly fingerprinted and excluded; every tracked/index mutation and any
 * other untracked path fails closed before the daemon is built or started.
 */
export function captureCertifiedDaemonSourceBasis({
  repo,
  binaryPath = path.join(repo, "target/debug/hypervisor-daemon"),
  allowedUntrackedPaths = ["0"],
  build = true,
}) {
  const sourceCommit = run("git", ["rev-parse", "HEAD"], repo);
  const sourceTree = run("git", ["rev-parse", "HEAD^{tree}"], repo);
  if (!/^[0-9a-f]{40}$/u.test(sourceCommit) || !/^[0-9a-f]{40}$/u.test(sourceTree)) {
    throw new Error("certified source basis did not resolve full Git commit and tree identities");
  }
  const trackedStatus = run(
    "git",
    ["status", "--porcelain=v1", "--untracked-files=no"],
    repo,
  );
  if (trackedStatus !== "") {
    throw new Error("certified daemon source has tracked or index mutations");
  }
  const untrackedRaw = run(
    "git",
    ["ls-files", "--others", "--exclude-standard", "-z"],
    repo,
  );
  const untracked = Buffer.from(untrackedRaw)
    .toString("utf8")
    .split("\0")
    .filter(Boolean)
    .sort();
  const allowed = [...allowedUntrackedPaths].sort();
  const unexpected = untracked.filter((entry) => !allowed.includes(entry));
  if (unexpected.length > 0) {
    throw new Error(`certified daemon source has unexpected untracked paths: ${unexpected.join(", ")}`);
  }
  const excludedUntracked = untracked.map((entry) => {
    const absolute = path.join(repo, entry);
    const metadata = lstatSync(absolute);
    if (!metadata.isFile()) {
      throw new Error(`certified source exclusion is not a regular file: ${entry}`);
    }
    return {
      path: entry,
      sha256: sha256(readFileSync(absolute)),
      size_bytes: metadata.size,
    };
  });

  const buildCommand = ["cargo", "build", "-p", "ioi-node", "--bin", "hypervisor-daemon"];
  if (build) run(buildCommand[0], buildCommand.slice(1), repo);
  const daemonBytes = readFileSync(binaryPath);
  return {
    schema_version: "ioi.hypervisor.certified-daemon-source-basis.v1",
    source_commit: sourceCommit,
    source_tree: sourceTree,
    source_dirty_state: "clean",
    publication_eligible: true,
    clean_scope: "tracked_files_and_index_with_explicit_non_build_untracked_exclusions",
    excluded_untracked: excludedUntracked,
    build_command: buildCommand.join(" "),
    build_profile: "debug",
    daemon_binary_sha256: sha256(daemonBytes),
    daemon_binary_size_bytes: daemonBytes.length,
  };
}

export function normalizeCertifiedSourceBasisForLifecycle(document) {
  const source = document?.schema_version === "ioi.hypervisor.certified-daemon-source-basis.v1"
    ? {
        commit: document.source_commit,
        daemon_binary_sha256: document.daemon_binary_sha256,
        dirty_state_declaration: document.source_dirty_state,
        publication_eligible: document.publication_eligible,
      }
    : document?.source || null;
  if (!source?.commit
      || !source?.daemon_binary_sha256
      || typeof source?.dirty_state_declaration !== "string"
      || typeof source?.publication_eligible !== "boolean") {
    throw new Error("source-basis certificate lacks commit, binary hash, dirty-state declaration, or publication posture");
  }
  return source;
}
