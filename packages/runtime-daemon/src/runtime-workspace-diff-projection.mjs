import { execFile } from "node:child_process";
import { readdir, readFile, stat } from "node:fs/promises";
import path from "node:path";

import { optionalString, safeId } from "./runtime-value-helpers.mjs";

export const WORKSPACE_DIFF_PROJECTION_SCHEMA_VERSION =
  "ioi.hypervisor.workspace_diff_projection.v1";

const IGNORED_DIRS = new Set([".git", "node_modules", ".cache", "dist"]);
const MAX_FILES = 500;

function runGitDefault(args, cwd) {
  return new Promise((resolve) => {
    execFile(
      "git",
      args,
      { cwd, timeout: 5000, maxBuffer: 8 * 1024 * 1024 },
      (error, stdout) => {
        if (error) resolve({ ok: false, stdout: "" });
        else resolve({ ok: true, stdout: String(stdout) });
      },
    );
  });
}

function statusLabel(code) {
  if (code.includes("D")) return "deleted";
  if (code.includes("A") || code === "??") return "added";
  return "modified";
}

function groupByFolder(files) {
  const groups = new Map();
  for (const file of files) {
    const folder = file.folder;
    if (!groups.has(folder)) {
      groups.set(folder, {
        group_ref: `changed-group:${safeId(folder || "root")}`,
        folder: folder || "./",
        files: [],
      });
    }
    groups.get(folder).files.push({
      file_ref: `changed-file:${safeId(file.relPath)}`,
      name: path.basename(file.relPath),
      delta: file.delta,
      status: file.status,
      receipt_ref: `receipt://changes/${safeId(file.relPath)}`,
    });
  }
  return [...groups.values()];
}

async function walkWorkspace(root, readDir, readFileImpl) {
  const out = [];
  async function walk(dir, rel) {
    let entries;
    try {
      entries = await readDir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (out.length >= MAX_FILES) return;
      if (entry.isDirectory()) {
        if (IGNORED_DIRS.has(entry.name)) continue;
        await walk(path.join(dir, entry.name), path.join(rel, entry.name));
      } else if (entry.isFile()) {
        const relPath = path.join(rel, entry.name);
        let lines = 0;
        try {
          const content = await readFileImpl(path.join(dir, entry.name), "utf8");
          lines = content.length === 0 ? 0 : content.split("\n").length;
        } catch {
          lines = 0;
        }
        out.push({
          relPath,
          folder: path.dirname(relPath) === "." ? "" : `${path.dirname(relPath)}/`,
          delta: `+${lines}`,
          status: "added",
        });
      }
    }
  }
  await walk(root, "");
  return out;
}

/**
 * Compute a real changed-file projection for a session workspace. When the
 * workspace is a git work tree the projection is `git status` + `git diff
 * --numstat` deltas; otherwise (a fresh scratch workspace) it is a real file
 * walk reporting every file as added. No fixtures — the signal is the disk.
 */
export async function computeWorkspaceDiffProjection(input = {}, deps = {}) {
  const workspaceRoot = optionalString(input.workspaceRoot);
  if (!workspaceRoot) {
    return {
      schema_version: WORKSPACE_DIFF_PROJECTION_SCHEMA_VERSION,
      workspace_root: null,
      source: "absent",
      changed_file_groups: [],
      runtimeTruthSource: "daemon-runtime",
    };
  }
  const runGit = typeof deps.runGit === "function" ? deps.runGit : runGitDefault;
  const readDir = deps.readDir ?? readdir;
  const readFileImpl = deps.readFile ?? readFile;

  const isRepo = await runGit(
    ["rev-parse", "--is-inside-work-tree"],
    workspaceRoot,
  );

  let files;
  let source;
  if (isRepo.ok && isRepo.stdout.trim() === "true") {
    source = "git";
    const numstat = await runGit(["diff", "--numstat", "HEAD"], workspaceRoot);
    const numstatByPath = new Map();
    for (const line of numstat.stdout.split("\n")) {
      const match = line.match(/^(\d+|-)\t(\d+|-)\t(.+)$/);
      if (match) numstatByPath.set(match[3], { added: match[1], removed: match[2] });
    }
    const status = await runGit(["status", "--porcelain"], workspaceRoot);
    files = [];
    for (const line of status.stdout.split("\n")) {
      if (!line.trim()) continue;
      const code = line.slice(0, 2).trim();
      const relPath = line.slice(3).trim();
      const nums = numstatByPath.get(relPath);
      const delta = nums
        ? `+${nums.added === "-" ? 0 : nums.added}/-${nums.removed === "-" ? 0 : nums.removed}`
        : "+0";
      files.push({
        relPath,
        folder:
          path.dirname(relPath) === "." ? "" : `${path.dirname(relPath)}/`,
        delta,
        status: statusLabel(code),
      });
    }
  } else {
    source = "filesystem";
    let exists = false;
    try {
      exists = (await stat(workspaceRoot)).isDirectory();
    } catch {
      exists = false;
    }
    files = exists
      ? await walkWorkspace(workspaceRoot, readDir, readFileImpl)
      : [];
  }

  return {
    schema_version: WORKSPACE_DIFF_PROJECTION_SCHEMA_VERSION,
    workspace_root: workspaceRoot,
    source,
    changed_file_groups: groupByFolder(files),
    changed_file_count: files.length,
    runtimeTruthSource: "daemon-runtime",
  };
}
