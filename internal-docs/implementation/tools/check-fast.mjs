#!/usr/bin/env node
// LANE 1 — fast development check.
//
//   node tools/check-fast.mjs
//
// Runs only what the current change can have broken:
//   * work-item records that actually differ from HEAD (or all, if none differ)
//   * canon impact for the canon subjects that actually changed
//   * estate structure and links scoped to the changed directories
//
// It never re-runs a whole-estate walk, a whole-repository scan, or a full
// journey when its inputs are unchanged. Stage certification and the program
// audit are separate lanes on purpose.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  finding,
  readJson,
  REPO_ROOT,
  report,
  sha256File,
} from "./lib/estate.mjs";
import { computeImpact } from "./canon-impact.mjs";
import { loadWorkItems, statusAuthority } from "./generate-now.mjs";
import { runEstateChecks } from "./check-estate.mjs";
import { applyWaivers, validateRecord } from "./check-work-item-shape.mjs";

function changedPaths() {
  try {
    const out = execFileSync(
      "git",
      ["status", "--porcelain", "--untracked-files=all"],
      { cwd: REPO_ROOT, encoding: "utf8" },
    );
    return out
      .split("\n")
      .map((l) => l.slice(3).trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

// The private estate is gitignored, so git cannot report its diffs. Fall back to
// mtime against the last fast-lane run, which is what makes a source-only edit
// cheap without pretending git sees it.
function changedEstateFiles() {
  const stampPath = path.join(ESTATE_ROOT, "generated", ".fast-lane-stamp");
  const since = fs.existsSync(stampPath)
    ? fs.statSync(stampPath).mtimeMs
    : 0;
  const out = [];
  const stack = [ESTATE_ROOT];
  const skip = new Set(["generated", "_archive", "node_modules", ".git"]);
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (skip.has(entry.name)) continue;
        stack.push(path.join(dir, entry.name));
      } else {
        const abs = path.join(dir, entry.name);
        // A dangling symlink (a nested worktree pointing at a build artifact
        // that was cleaned) has no mtime. It is not a changed estate file, and
        // it is certainly not a reason for the fast lane to crash instead of
        // reporting. Skipping it changes no verdict.
        let mtimeMs = null;
        try {
          mtimeMs = fs.statSync(abs).mtimeMs;
        } catch {
          continue;
        }
        if (mtimeMs > since) {
          out.push(path.relative(ESTATE_ROOT, abs));
        }
      }
    }
  }
  return { files: out, since, stampPath };
}

function main() {
  const started = Date.now();
  const findings = [];
  const { files: estateChanged, since, stampPath } = changedEstateFiles();
  const repoChanged = changedPaths();

  const changedWorkItems = estateChanged.filter((f) =>
    f.startsWith("work-items/") && f.endsWith(".v1.json")
  );
  const changedScopes = [
    ...new Set(
      estateChanged
        .map((f) => (f.includes("/") ? `${f.split("/")[0]}/` : null))
        .filter(Boolean),
    ),
  ];

  // --- 1. shape-validate only the records that changed
  const records = loadWorkItems();
  const targets = changedWorkItems.length > 0
    ? records.filter((r) => changedWorkItems.includes(r.file))
    : (since === 0 ? records : []);
  for (const record of targets) {
    findings.push(...validateRecord(record));
  }

  // --- 2. canon impact, bounded to what changed
  const impact = computeImpact({ repoRoot: REPO_ROOT, estateRoot: ESTATE_ROOT });
  const canonChangedInThisEdit = repoChanged.some((p) => p.startsWith("docs/"));
  findings.push(
    ...impact.findings.filter((f) =>
      f.level === "error" &&
      (canonChangedInThisEdit ||
        f.check === "canon-orphan" ||
        f.check === "canon-binding" ||
        f.check === "module-orphan")
    ),
  );
  if (canonChangedInThisEdit && impact.impact.changed.length > 0) {
    findings.push(
      finding(
        "warn",
        "canon-review",
        `canon changed; review stages ${
          impact.affected.stages.join(", ") || "(none)"
        } and ${impact.affected.work_items.length} work item(s), then run canon-impact --accept`,
      ),
    );
  }

  // --- 3. estate structure, scoped to the changed directories
  const scopes = changedScopes.length > 0 && since !== 0 ? changedScopes : [null];
  for (const scope of scopes) {
    findings.push(...runEstateChecks({ scope }));
  }

  // --- 4. status authority never silently diverges
  for (const record of records) {
    const authority = statusAuthority(record);
    if (!authority.agrees) {
      findings.push(
        finding(
          "error",
          "status-authority",
          `${record.work_item_id}: private mirror (${authority.private_status}) disagrees with its status authority ${authority.ref} (${authority.status}); run tools/reconcile-status.mjs`,
        ),
      );
    }
  }

  const waived = applyWaivers(findings);
  const failed = waived.some((f) => f.level === "error");

  // The stamp advances ONLY on a clean run. Advancing it after a failure would
  // make the offending file "unchanged" on the next invocation, so a real defect
  // would be reported exactly once and then vanish. A lane that goes green by
  // forgetting is worse than no lane.
  if (!failed) {
    fs.mkdirSync(path.dirname(stampPath), { recursive: true });
    fs.writeFileSync(stampPath, `${new Date().toISOString()}\n`);
  }

  const elapsed = ((Date.now() - started) / 1000).toFixed(2);
  process.stdout.write(
    `fast lane: ${targets.length} work item(s), ${
      scopes.filter(Boolean).length || "all"
    } scope(s), ${impact.subjects.length} canon subjects — ${elapsed}s${
      failed ? " — stamp NOT advanced; the next run re-checks the same inputs" : ""
    }\n`,
  );
  process.exit(report("check-fast", waived));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
