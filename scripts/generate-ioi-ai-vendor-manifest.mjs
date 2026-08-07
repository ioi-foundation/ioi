#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const vendorRoot = "apps/ioi-ai";
const manifestPath = path.join(
  root,
  "docs",
  "architecture",
  "_meta",
  "ioi-ai-vendor-snapshot.v1.json",
);
const write = process.argv.includes("--write");

function gitBlobHash(bytes) {
  const header = Buffer.from(`blob ${bytes.length}\0`);
  return crypto.createHash("sha1").update(header).update(bytes).digest("hex");
}

function gitModeAndBytes(relativePath) {
  const absolutePath = path.join(root, relativePath);
  const stat = fs.lstatSync(absolutePath);
  if (stat.isSymbolicLink()) {
    return {
      gitMode: "120000",
      bytes: Buffer.from(fs.readlinkSync(absolutePath)),
    };
  }
  if (!stat.isFile()) {
    throw new Error(`unsupported vendor entry type: ${relativePath}`);
  }
  return {
    gitMode: stat.mode & 0o111 ? "100755" : "100644",
    bytes: fs.readFileSync(absolutePath),
  };
}

const indexEntries = execFileSync(
  "git",
  ["ls-files", "--stage", "-z", "--", vendorRoot],
  { cwd: root, encoding: "utf8" },
)
  .split("\0")
  .filter(Boolean)
  .map((entry) => {
    const match = /^(\d{6}) ([0-9a-f]{40}) (\d)\t([\s\S]+)$/u.exec(entry);
    if (!match) throw new Error(`cannot parse Git index entry: ${entry}`);
    const [, gitMode, gitBlobSha1, stage, relativePath] = match;
    if (stage !== "0") {
      throw new Error(
        `unmerged vendor entry is not admissible: ${relativePath}`,
      );
    }
    return { gitMode, gitBlobSha1, path: relativePath };
  })
  .sort((left, right) => left.path.localeCompare(right.path));

const untracked = execFileSync(
  "git",
  ["ls-files", "--others", "--exclude-standard", "-z", "--", vendorRoot],
  { cwd: root, encoding: "utf8" },
)
  .split("\0")
  .filter(Boolean)
  .sort();
if (untracked.length > 0) {
  throw new Error(
    `untracked files exist inside the pinned vendor root: ${untracked.join(", ")}`,
  );
}

const files = indexEntries.map((indexEntry) => {
  const live = gitModeAndBytes(indexEntry.path);
  const liveBlobSha1 = gitBlobHash(live.bytes);
  if (
    live.gitMode !== indexEntry.gitMode ||
    liveBlobSha1 !== indexEntry.gitBlobSha1
  ) {
    throw new Error(
      `${indexEntry.path} differs from its Git index identity (${indexEntry.gitMode} ${indexEntry.gitBlobSha1}); got ${live.gitMode} ${liveBlobSha1}`,
    );
  }
  return {
    path: indexEntry.path,
    git_mode: live.gitMode,
    git_blob_sha1: liveBlobSha1,
  };
});

// apps/ioi-ai is a FORK, not a pin: by owner ruling of 2026-08-07 it is the one
// ioi.ai application and it receives IOI modifications directly. Provenance is
// therefore per-file, so a reader can still tell what came from upstream, what
// IOI changed, and what IOI wrote.
const baselinePath = path.join(root, "docs", "architecture", "_meta", "ioi-ai-upstream-baseline.v1.json");
const baseline = fs.existsSync(baselinePath)
  ? new Map(JSON.parse(fs.readFileSync(baselinePath, "utf8")).files.map((f) => [f.path, f.git_blob_sha1]))
  : new Map();

for (const entry of files) {
  const upstream = baseline.get(entry.path);
  if (upstream === undefined) {
    entry.provenance = "ioi_owned";
  } else if (upstream === entry.git_blob_sha1) {
    entry.provenance = "vendored";
  } else {
    entry.provenance = "vendored_then_modified";
    entry.upstream_blob_sha1 = upstream;
  }
}

const tally = files.reduce((a, f) => ((a[f.provenance] = (a[f.provenance] ?? 0) + 1), a), {});

const manifest = {
  schema_version: "ioi.vendor-snapshot.v2",
  vendor_root: vendorRoot,
  upstream_repository: "https://github.com/yc-software/qm.git",
  upstream_commit: "5eb3393315b45b338b860572ab516db9f6eae6da",
  upstream_identity_verification: "not_performed",
  posture: "fork — apps/ioi-ai is the single ioi.ai application and receives IOI modifications directly (owner ruling 2026-08-07). This ledger records per-file provenance; it no longer asserts byte identity with upstream.",
  upstream_baseline_ref: "docs/architecture/_meta/ioi-ai-upstream-baseline.v1.json",
  adopted_file_count: files.length,
  provenance_tally: tally,
  files,
};

const rendered = `${JSON.stringify(manifest, null, 2)}\n`;
if (write) {
  fs.writeFileSync(manifestPath, rendered);
  process.stdout.write(`wrote ${files.length} vendor file hashes\n`);
} else {
  if (!fs.existsSync(manifestPath))
    throw new Error("ioi.ai vendor snapshot is missing; run with --write");
  const existing = fs.readFileSync(manifestPath, "utf8");
  if (existing !== rendered) {
    throw new Error(
      "apps/ioi-ai differs from the committed vendor ledger; refresh it deliberately with --write and review the provenance tally",
    );
  }
  process.stdout.write(
    `ioi.ai vendor ledger: ${files.length} files verified — ${JSON.stringify(tally)}\n`,
  );
}
